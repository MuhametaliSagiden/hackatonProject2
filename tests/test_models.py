import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, create_engine

from radar.models import NotificationLog, Service


def test_service_host_port_is_unique(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'models.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Service(host="same.example", port=443), Service(host="same.example", port=443)])
        with pytest.raises(IntegrityError):
            db.commit()


def test_successful_notification_key_is_unique(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'notifications.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                NotificationLog(
                    service_id=1,
                    thumbprint_sha1="same-thumbprint",
                    threshold=30,
                    channel="console",
                    success=True,
                    message="one",
                ),
                NotificationLog(
                    service_id=1,
                    thumbprint_sha1="same-thumbprint",
                    threshold=30,
                    channel="console",
                    success=True,
                    message="two",
                ),
            ]
        )
        with pytest.raises(IntegrityError):
            db.commit()
