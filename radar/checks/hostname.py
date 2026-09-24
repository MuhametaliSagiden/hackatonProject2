from ipaddress import ip_address

from ..recommendations import create_finding
from .base import CheckContext, Finding


def matches(host: str, pattern: str) -> bool:
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if p.startswith("*."):
        # Wildcard only allowed if * occupies entire leftmost label and covers exactly one label
        # Rest of pattern must not contain wildcard
        rest = p[2:]
        if "*" in rest:
            return False
        suffix = p[1:]  # e.g. .a.com
        return h.endswith(suffix) and h.count(".") == p.count(".") and len(h) > len(suffix)
    return h == p


class HostnameCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable:
            ctx.hostname_match = None
            return []

        host = ctx.service.host
        try:
            target_ip = ip_address(host)
            san_ips = ctx.raw.san_ip or []
            matched = str(target_ip) in [str(x) for x in san_ips]
            ctx.hostname_match = matched
            if not matched:
                names_str = ", ".join(str(x) for x in san_ips) if san_ips else "нет"
                return [create_finding("HOSTNAME_MISMATCH", severity="high", host=host, names=names_str)]
            return []
        except ValueError:
            pass

        names = list(ctx.raw.san_dns or [])
        if not names and ctx.raw.subject_cn:
            names = [ctx.raw.subject_cn]

        matched = any(matches(host, name) for name in names) if names else False
        ctx.hostname_match = matched

        if not matched:
            names_str = ", ".join(names) if names else (ctx.raw.subject_cn or "нет")
            return [create_finding("HOSTNAME_MISMATCH", severity="high", host=host, names=names_str)]
        return []
