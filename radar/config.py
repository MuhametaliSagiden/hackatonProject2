import os
import shutil
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "thresholds": {"info_days": 60, "warning_days": 30, "critical_days": 14},
    "notify_thresholds": [60, 30, 14, 7, 1],
    "scan": {"timeout_sec": 5, "workers": 32, "max_cidr_hosts": 256, "schedule_hours": 0},
    "dns_overrides": {},
    "trust": {"extra_ca_files": []},
    "notify": {
        "email_enabled": False,
        "smtp_host": "",
        "smtp_port": 25,
        "smtp_from": "radar@localhost",
        "email_to": [],
        "telegram_enabled": False,
    },
}


def load_env(path: Path | None = None) -> None:
    env_file = path or ROOT / ".env"
    if not env_file.exists():
        return
    try:
        content = env_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, val = stripped.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            if key:
                os.environ[key] = val
    except Exception:  # noqa: S110
        pass


def load_config(path: Path | None = None, override_from_db: bool = True) -> dict[str, Any]:
    load_env()
    value: dict[str, Any] = {
        "thresholds": dict(DEFAULTS["thresholds"]),
        "notify_thresholds": list(DEFAULTS["notify_thresholds"]),
        "scan": dict(DEFAULTS["scan"]),
        "dns_overrides": dict(DEFAULTS["dns_overrides"]),
        "trust": dict(DEFAULTS["trust"]),
        "notify": dict(DEFAULTS["notify"]),
    }

    target = path or ROOT / "config.yaml"
    example = ROOT / "config.example.yaml"
    if not target.exists() and example.exists():
        try:
            shutil.copy2(example, target)
        except Exception:  # noqa: S110
            pass

    if target.exists():
        try:
            with target.open(encoding="utf-8") as stream:
                loaded = yaml.safe_load(stream) or {}
            for key, data in loaded.items():
                if isinstance(data, dict) and isinstance(value.get(key), dict):
                    value[key] = {**value[key], **data}
                else:
                    value[key] = data
        except Exception:  # noqa: S110
            pass

    if override_from_db:
        try:
            from sqlmodel import select
            from .db import session
            from .models import Setting

            with session() as db:
                settings_map = {s.key: s.value for s in db.exec(select(Setting))}
                if "info_days" in settings_map:
                    value["thresholds"]["info_days"] = int(settings_map["info_days"])
                if "warning_days" in settings_map:
                    value["thresholds"]["warning_days"] = int(settings_map["warning_days"])
                if "critical_days" in settings_map:
                    value["thresholds"]["critical_days"] = int(settings_map["critical_days"])
                if "notify_thresholds" in settings_map:
                    val = settings_map["notify_thresholds"]
                    if isinstance(val, list):
                        value["notify_thresholds"] = [int(x) for x in val]
                    elif isinstance(val, str):
                        value["notify_thresholds"] = [int(x.strip()) for x in val.split(",") if x.strip()]
                if "schedule_hours" in settings_map:
                    value["scan"]["schedule_hours"] = int(settings_map["schedule_hours"])
                for k in [
                    "email_enabled",
                    "smtp_host",
                    "smtp_port",
                    "smtp_from",
                    "email_to",
                    "telegram_enabled",
                ]:
                    if k in settings_map:
                        value["notify"][k] = settings_map[k]
        except Exception:  # noqa: S110
            pass

    return value
