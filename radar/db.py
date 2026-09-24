import os
from pathlib import Path

from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = Path("data/radar.db")
_engine = None


def get_db_path() -> Path:
    env_path = os.getenv("RADAR_DB_PATH")
    if env_path:
        return Path(env_path)
    return DB_PATH


def get_engine(db_path: Path | str | None = None):
    global _engine
    target = Path(db_path) if db_path else get_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if _engine is None or db_path is not None:
        _engine = create_engine(
            f"sqlite:///{target.as_posix()}",
            connect_args={"check_same_thread": False},
        )
    return _engine


# Default engine for backwards compatibility
engine = get_engine()


def init_db(engine_instance=None):
    eng = engine_instance or get_engine()
    # Ensure data/ and logs/ exist as per specification
    db_p = get_db_path()
    db_p.parent.mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)

    SQLModel.metadata.create_all(eng)

    # Safe SQLite schema migration: ensure indexes and constraints exist
    with eng.connect() as conn:
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_service_host_port ON service (host, port);"))
        conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_notification_success "
                "ON notificationlog (thumbprint_sha1, threshold, channel) "
                "WHERE success = 1;"
            )
        )
        conn.commit()


def get_session(engine_instance=None) -> Session:
    eng = engine_instance or get_engine()
    init_db(eng)
    return Session(eng, expire_on_commit=False)


def session(engine_instance=None) -> Session:
    return get_session(engine_instance)
