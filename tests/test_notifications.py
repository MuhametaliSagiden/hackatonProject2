from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, select

from radar.models import CertResult, NotificationLog, Service
from radar.notify.service import notify_after_scan


def make_notification_db(tmp_path: Path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'notifications.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    return engine


def test_notification_module_has_public_entrypoint():
    assert callable(notify_after_scan)
    assert NotificationLog.__tablename__ == "notificationlog"


def test_notification_thresholds_are_deduplicated(tmp_path, monkeypatch):
    engine = make_notification_db(tmp_path)
    service = Service(host="example.test", port=443, service_name="Почта OWA", owner="owner@example")
    with Session(engine) as db:
        db.add(service)
        db.commit()
        db.refresh(service)
        for index, days_left in enumerate((5, 25, 45, -1), start=1):
            db.add(
                CertResult(
                    scan_id=1,
                    service_id=service.id,
                    reachable=True,
                    thumbprint_sha1=f"thumbprint-{index}",
                    days_left=days_left,
                    risk_score=70,
                    risk_level="High",
                    findings=[{"recommendation": "Запланируйте перевыпуск."}],
                )
            )
        db.commit()

    monkeypatch.setattr("radar.notify.service.session", lambda: Session(engine))
    sent = []

    class Channel:
        def send(self, message):
            sent.append(message)
            return True

    monkeypatch.setattr(
        "radar.notify.service.get_active_channels",
        lambda config=None: {"console": Channel()},
    )
    monkeypatch.setattr("radar.notify.service.load_config", lambda: {"notify_thresholds": [60, 30, 14, 7, 1]})
    monkeypatch.setattr("radar.notify.service.audit", lambda *args, **kwargs: None)

    assert notify_after_scan(1) == 4
    assert notify_after_scan(1) == 0
    assert len(sent) == 4

    with Session(engine) as db:
        logs = list(db.exec(select(NotificationLog)))
    assert {log.threshold for log in logs} == {0, 7, 30, 60}
    assert all(log.success for log in logs)
    assert "Почта OWA" in logs[0].message
    assert "Запланируйте перевыпуск." in logs[0].message


def test_failed_notification_channel_is_logged(tmp_path, monkeypatch):
    engine = make_notification_db(tmp_path)
    with Session(engine) as db:
        service = Service(host="example.test")
        db.add(service)
        db.commit()
        db.refresh(service)
        db.add(
            CertResult(
                scan_id=2,
                service_id=service.id,
                reachable=True,
                thumbprint_sha1="failed-thumbprint",
                days_left=5,
                risk_score=80,
                risk_level="Critical",
            )
        )
        db.commit()

    monkeypatch.setattr("radar.notify.service.session", lambda: Session(engine))

    class FailedChannel:
        def send(self, message):
            raise RuntimeError("SMTP недоступен")

    monkeypatch.setattr(
        "radar.notify.service.get_active_channels",
        lambda config=None: {"email": FailedChannel()},
    )
    monkeypatch.setattr("radar.notify.service.load_config", lambda: {"notify_thresholds": [7]})
    monkeypatch.setattr("radar.notify.service.audit", lambda *args, **kwargs: None)

    assert notify_after_scan(2) == 0
    with Session(engine) as db:
        log = db.exec(select(NotificationLog)).one()
    assert log.success is False
    assert "example.test" in log.message
