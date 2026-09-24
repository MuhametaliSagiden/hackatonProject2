from time import monotonic

from sqlmodel import Session, SQLModel, create_engine, select

from radar.models import CertResult, Service
from radar.scanner.engine import run_scan
from radar.scanner.tls import RawResult


def test_scan_handles_256_unreachable_targets_in_isolated_db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'load.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Service(host=f"10.250.0.{index}", port=8499) for index in range(1, 257)])
        db.commit()

    monkeypatch.setattr(
        "radar.scanner.engine.session",
        lambda: Session(engine, expire_on_commit=False),
    )
    monkeypatch.setattr(
        "radar.scanner.engine.load_config",
        lambda: {
            "scan": {"workers": 32, "timeout_sec": 0.01},
            "dns_overrides": {},
            "trust": {"extra_ca_files": []},
            "thresholds": {"info_days": 60, "warning_days": 30, "critical_days": 14},
        },
    )
    monkeypatch.setattr("radar.scanner.engine.grab", lambda *args, **kwargs: RawResult(False, "unreachable"))
    monkeypatch.setattr("radar.scanner.engine.audit", lambda *args, **kwargs: None)
    monkeypatch.setattr("radar.scanner.engine.notify_after_scan", lambda scan_id: 0)

    started = monotonic()
    scan = run_scan(triggered_by="load-test")
    elapsed = monotonic() - started

    assert scan.status == "done"
    assert scan.total == 256
    assert scan.processed == 256
    assert elapsed < 5

    with Session(engine) as db:
        results = list(db.exec(select(CertResult).where(CertResult.scan_id == scan.id)))
    assert len(results) == 256
    assert all(result.status == "Unreachable" for result in results)
    assert all(result.risk_score is None for result in results)
