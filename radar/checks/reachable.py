from ..recommendations import create_finding
from .base import CheckContext, Finding


class ReachableCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.raw.reachable:
            return []
        return [
            create_finding(
                "UNREACHABLE",
                severity="high",
                error=getattr(ctx.raw, "error", None) or "неизвестная ошибка",
            )
        ]
