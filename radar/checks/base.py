from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol


@dataclass
class Finding:
    code: str
    severity: str = "low"
    reason: str = ""
    recommendation: str = ""


class CheckContext:
    def __init__(
        self,
        raw: Any,
        service: Any,
        settings: dict[str, int] | None = None,
        now: datetime | None = None,
    ):
        self.raw = raw
        self.service = service
        self.settings = settings or {"info_days": 60, "warning_days": 30, "critical_days": 14}
        self.now = now or datetime.now(UTC)
        self.days_left: int | None = None
        self.status: str = "Unreachable" if not getattr(raw, "reachable", False) else "OK"
        self.self_signed: bool | None = None
        self.hostname_match: bool | None = None
        self.weak_crypto: bool | None = None
        self.chain_status: str = "unknown"
        self.findings: list[Finding] = []


class Check(Protocol):
    def run(self, ctx: CheckContext) -> list[Finding]: ...
