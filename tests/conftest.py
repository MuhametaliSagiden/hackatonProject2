import os
import tempfile
from pathlib import Path


def pytest_sessionstart(session):
    test_db = Path(tempfile.mkdtemp(prefix="certificate-radar-tests-")) / "radar.db"
    os.environ["RADAR_DB_PATH"] = str(test_db)
