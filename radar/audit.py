import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .db import session
from .models import AuditLog


def audit(action: str, details: dict[str, Any] | str | None = None):
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("radar")
    if not logger.handlers:
        handler = RotatingFileHandler(
            log_dir / "radar.log",
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    if isinstance(details, dict):
        payload = details
    elif isinstance(details, str):
        try:
            payload = json.loads(details)
        except Exception:
            payload = {"raw": details}
    else:
        payload = {}

    logger.info("%s %s", action, payload)
    db = session()
    try:
        db.add(AuditLog(action=action, details=payload))
        db.commit()
    finally:
        db.close()
