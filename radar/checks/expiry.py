import math
from ..recommendations import create_finding
from .base import CheckContext, Finding


def status_for_days(days: int, thresholds: dict[str, int]) -> str:
    if days < 0:
        return "Expired"
    if days <= thresholds["critical_days"]:
        return "Critical"
    if days <= thresholds["warning_days"]:
        return "Warning"
    if days <= thresholds["info_days"]:
        return "Information"
    return "OK"


class ExpiryCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable or not ctx.raw.not_after:
            return []
        seconds = (ctx.raw.not_after - ctx.now).total_seconds()
        days = math.floor(seconds / 86400)
        ctx.days_left = days
        status = status_for_days(days, ctx.settings)
        ctx.status = status

        findings: list[Finding] = []
        if days < 0:
            findings.append(create_finding("EXPIRED", severity="high", days=abs(days)))
        elif status == "Critical":
            findings.append(create_finding("EXPIRING", severity="high", days=days))
        elif status == "Warning":
            findings.append(create_finding("EXPIRING", severity="medium", days=days))
        elif status == "Information":
            findings.append(create_finding("EXPIRING", severity="low", days=days))
        return findings
