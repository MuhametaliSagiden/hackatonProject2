from ..recommendations import create_finding
from .base import CheckContext, Finding


def weak_key(key_type: str | None, key_size: int | None) -> bool:
    if not key_size:
        return False
    if key_type == "RSA" and key_size < 2048:
        return True
    return bool(key_type == "EC" and key_size < 256)


def weak_signature(sig_hash: str | None) -> bool:
    if not sig_hash:
        return False
    return sig_hash.lower() in {"md5", "sha1"}


class CryptoCheck:
    def run(self, ctx: CheckContext) -> list[Finding]:
        if not ctx.raw.reachable:
            ctx.weak_crypto = None
            return []

        findings: list[Finding] = []
        is_weak_k = weak_key(ctx.raw.key_type, ctx.raw.key_size)
        is_weak_s = weak_signature(ctx.raw.sig_hash)
        ctx.weak_crypto = is_weak_k or is_weak_s

        if is_weak_k:
            findings.append(
                create_finding(
                    "WEAK_KEY",
                    severity="medium",
                    bits=ctx.raw.key_size or "неизвестно",
                )
            )
        if is_weak_s:
            findings.append(
                create_finding(
                    "WEAK_SIGNATURE",
                    severity="medium",
                    hash=ctx.raw.sig_hash or "неизвестно",
                )
            )
        return findings
