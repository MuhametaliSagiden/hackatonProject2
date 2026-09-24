from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {"thresholds": {"info_days": 60, "warning_days": 30, "critical_days": 14}, "notify_thresholds": [60, 30, 14, 7, 1], "scan": {"timeout_sec": 5, "workers": 32, "max_cidr_hosts": 256}, "dns_overrides": {}, "trust": {"extra_ca_files": []}}

def load_config(path: Path | None = None) -> dict:
    value = DEFAULTS.copy()
    if path and path.exists():
        with path.open(encoding="utf-8") as stream:
            loaded = yaml.safe_load(stream) or {}
        for key, data in loaded.items():
            value[key] = {**value.get(key, {}), **data} if isinstance(data, dict) else data
    return value
