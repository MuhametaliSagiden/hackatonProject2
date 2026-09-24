from pathlib import Path
from typing import Any

import yaml

from .checks import Finding

_YAML_PATH = Path(__file__).resolve().parent / "recommendations_ru.yaml"
_TEMPLATES: dict[str, dict[str, str]] | None = None


def load_templates() -> dict[str, dict[str, str]]:
    global _TEMPLATES
    if _TEMPLATES is None:
        if _YAML_PATH.exists():
            with _YAML_PATH.open(encoding="utf-8") as f:
                _TEMPLATES = yaml.safe_load(f) or {}
        else:
            _TEMPLATES = {}
    return _TEMPLATES


class _SafeDict(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


def format_text(template: str, kwargs: dict[str, Any]) -> str:
    safe_map = _SafeDict({k: v for k, v in kwargs.items() if v is not None})
    return template.format_map(safe_map)


def get_recommendation(code: str, **kwargs) -> tuple[str, str]:
    templates = load_templates()
    item = templates.get(code, {})
    reason_tmpl = item.get("reason", "")
    rec_tmpl = item.get("recommendation", "")
    reason = format_text(reason_tmpl, kwargs) if reason_tmpl else ""
    rec = format_text(rec_tmpl, kwargs) if rec_tmpl else ""
    return reason, rec


def create_finding(code: str, severity: str = "low", **kwargs) -> Finding:
    reason, rec = get_recommendation(code, **kwargs)
    return Finding(code=code, severity=severity, reason=reason, recommendation=rec)
