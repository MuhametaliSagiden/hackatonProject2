from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

DB_PATH = Path("data/radar.db")
engine = create_engine(f"sqlite:///{DB_PATH.as_posix()}", connect_args={"check_same_thread": False})

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    SQLModel.metadata.create_all(engine)

def session():
    init_db()
    return Session(engine)
