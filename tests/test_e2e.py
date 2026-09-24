from datetime import UTC, datetime, timedelta
from time import monotonic

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from radar.models import CertResult, NotificationLog
from radar.scanner.engine import run_scan as engine_run_scan
from radar.scanner.tls import RawResult
from radar.targets.parser import parse_text
from radar.web.app import app


def test_web_navigation_and_exports():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/targets").status_code == 200
        assert client.get("/certificates").status_code == 200
        assert client.get("/scans").status_code == 200
        assert client.get("/audit").status_code == 200
        for endpoint in [
            "/api/dashboard",
            "/api/services",
            "/api/scans",
            "/api/certificates",
            "/api/audit",
            "/api/notifications",
        ]:
            assert client.get(endpoint).status_code == 200
        csv = client.get("/export?format=csv")
        assert csv.status_code == 200
        assert "text/csv" in csv.headers["content-type"]
        assert client.get("/export?format=xlsx").content.startswith(b"PK")
        assert "<table>" in client.get("/export?format=html").text


def test_cidr_limit_is_fast_and_bounded():
    started = monotonic()
    report = parse_text("127.0.0.0/24", max_cidr_hosts=256)
    assert len(report.services) == 254
    assert monotonic() - started < 1
    rejected = parse_text("10.0.0.0/16", max_cidr_hosts=256)
    assert len(rejected.invalid) == 1


def test_ui_scan_dashboard_card_export_and_notification(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'e2e.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    isolated_session = lambda: Session(engine, expire_on_commit=False)

    monkeypatch.setattr("radar.web.app.session", isolated_session)
    monkeypatch.setattr("radar.services.session", isolated_session)
    monkeypatch.setattr("radar.scanner.engine.session", isolated_session)
    monkeypatch.setattr("radar.notify.service.session", isolated_session)
    monkeypatch.setattr("radar.scanner.engine.audit", lambda *args, **kwargs: None)
    monkeypatch.setattr("radar.notify.service.audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "radar.scanner.engine.load_config",
        lambda: {
            "scan": {"workers": 2, "timeout_sec": 1},
            "dns_overrides": {},
            "trust": {"extra_ca_files": []},
            "thresholds": {"info_days": 60, "warning_days": 30, "critical_days": 14},
            "notify_thresholds": [7],
        },
    )
    monkeypatch.setattr("radar.notify.service.load_config", lambda: {"notify_thresholds": [7]})
    monkeypatch.setattr(
        "radar.scanner.engine.grab",
        lambda *args, **kwargs: RawResult(
            reachable=True,
            thumbprint_sha1="e2e-thumbprint",
            thumbprint_sha256="e2e-thumbprint-sha256",
            subject_cn="owa.example",
            san_dns=["owa.example"],
            issuer_cn="E2E CA",
            not_after=datetime.now(UTC) + timedelta(days=5),
            key_type="RSA",
            key_size=2048,
            sig_hash="sha256",
            chain_verify_code=0,
            chain_verify_message="OK",
            tls_version="TLSv1.3",
        ),
    )

    class Channel:
        def send(self, message):
            return True

    monkeypatch.setattr(
        "radar.notify.service.get_active_channels", lambda config=None: {"console": Channel()}
    )
    monkeypatch.setattr(
        "radar.web.app.run_scan_background",
        lambda triggered_by: engine_run_scan(triggered_by=triggered_by),
    )

    with TestClient(app) as client:
        imported = client.post("/targets/import", data={"target_text": "owa.example"})
        assert imported.status_code == 200
        assert "Добавлено: 1" in imported.text

        started = client.post("/scans/start", follow_redirects=False)
        assert started.status_code == 303
        scan_id = int(started.headers["location"].rsplit("/", 1)[1])
        deadline = monotonic() + 5
        while monotonic() < deadline:
            scan = client.get("/api/scans").json()
            current = next(item for item in scan if item["id"] == scan_id)
            if current["status"] == "done":
                break
        assert current["status"] == "done"
        assert current["processed"] == 1

        assert client.get("/").status_code == 200
        filtered = client.get("/certificates?q=owa&status=Critical")
        assert filtered.status_code == 200
        assert "owa.example" in filtered.text

        result = client.get("/api/certificates").json()[0]
        card = client.get(f"/certificates/{result['id']}")
        assert card.status_code == 200
        assert "owa.example" in card.text
        assert client.get("/export?format=csv").status_code == 200
        notifications = client.get("/api/notifications").json()
        assert len(notifications) == 1

    with Session(engine) as db:
        assert len(list(db.exec(select(CertResult)))) == 1
        assert len(list(db.exec(select(NotificationLog)))) == 1
