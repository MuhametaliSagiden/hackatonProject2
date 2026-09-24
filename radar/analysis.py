from datetime import UTC, datetime
from typing import Any

from .checks import ALL_CHECKS, CheckContext, Finding
from .checks.hostname import matches as hostname_matches
from .recommendations import create_finding
from .risk import score


def analyze(
    raw: Any,
    service: Any,
    settings: dict[str, int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    settings = settings or {"info_days": 60, "warning_days": 30, "critical_days": 14}

    if not getattr(raw, "reachable", False):
        unreachable_finding = create_finding(
            "UNREACHABLE",
            severity="high",
            error=getattr(raw, "error", None) or "неизвестная ошибка",
        )
        return {
            "status": "Unreachable",
            "days_left": None,
            "findings": [unreachable_finding],
            "risk_score": None,
            "risk_level": "N/A",
            "hostname_match": None,
            "self_signed": None,
            "weak_crypto": None,
            "chain_status": "unknown",
        }

    ctx = CheckContext(raw=raw, service=service, settings=settings, now=now)
    findings: list[Finding] = []

    for check in ALL_CHECKS:
        findings.extend(check.run(ctx))

    points, level = score(
        ctx.status,
        findings,
        getattr(service, "criticality", "medium"),
        ctx.days_left,
    )

    return {
        "status": ctx.status,
        "days_left": ctx.days_left,
        "findings": findings,
        "risk_score": points,
        "risk_level": level,
        "hostname_match": ctx.hostname_match,
        "self_signed": ctx.self_signed,
        "weak_crypto": ctx.weak_crypto,
        "chain_status": ctx.chain_status,
    }


_hostname_matches = hostname_matches
