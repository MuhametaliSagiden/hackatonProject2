from cryptography import x509

from ..recommendations import create_finding
from .base import CheckContext, Finding


def is_self_signed(pem: str | None) -> bool:
    if not pem:
        return False
    try:
        data = pem.encode("utf-8") if isinstance(pem, str) else pem
        cert = x509.load_pem_x509_certificate(data)
        if cert.issuer != cert.subject:
            return False
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:
        return False


class SelfSignedCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable or not ctx.raw.leaf_pem:
            ctx.self_signed = False
            return []
        self_signed = is_self_signed(ctx.raw.leaf_pem)
        ctx.self_signed = self_signed
        if self_signed:
            return [create_finding("SELF_SIGNED", severity="high")]
        return []
