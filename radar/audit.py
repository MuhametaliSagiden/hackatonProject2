import json, logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from .db import session
from .models import AuditLog

def audit(action, details=None):
    Path("logs").mkdir(exist_ok=True); logger=logging.getLogger("radar")
    if not logger.handlers:
        logger.addHandler(RotatingFileHandler("logs/radar.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")); logger.setLevel(logging.INFO)
    payload=details or {}; logger.info("%s %s", action, payload); db=session(); db.add(AuditLog(action=action, details=json.dumps(payload, ensure_ascii=False))); db.commit(); db.close()
