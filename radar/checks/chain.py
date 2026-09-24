from ..recommendations import create_finding
from .base import CheckContext, Finding


def chain_status(verify_code: int | None, self_signed: bool = False) -> str:
    if self_signed or verify_code == 18:
        return "self_signed"
    if verify_code in (0, 9, 10):
        return "trusted"
    return "untrusted"


class ChainCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable:
            ctx.chain_status = "unknown"
            return []
        status = chain_status(ctx.raw.chain_verify_code, bool(ctx.self_signed))
        ctx.chain_status = status

        if status == "untrusted" and not ctx.self_signed:
            err_msg = ctx.raw.chain_verify_message or str(
                ctx.raw.chain_verify_code or "Недоверенный сертификат"
            )
            return [create_finding("CHAIN_ERROR", severity="high", error=err_msg)]
        return []
