from ..recommendations import create_finding
from .base import CheckContext, Finding


def missing_owner(owner: str | None) -> bool:
    return not bool(owner and owner.strip())


class OwnerCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable:
            return []
        if missing_owner(ctx.service.owner):
            return [create_finding("NO_OWNER", severity="low")]
        return []
