import hashlib
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .resolver import resolve


@dataclass
class RawResult:
    reachable: bool; error: str | None = None; resolved_ip: str | None = None; leaf_pem: str | None = None
    subject_cn: str | None = None; san_dns: list = None; san_ip: list = None; issuer_cn: str | None = None
    issuer_full: str | None = None; serial: str | None = None; thumbprint_sha1: str | None = None
    thumbprint_sha256: str | None = None; not_before: object = None; not_after: object = None
    key_type: str | None = None; key_size: int | None = None; sig_hash: str | None = None; tls_version: str | None = None
    chain_verify_code: int | None = None; chain_verify_message: str | None = None

def grab(host, port, timeout=5, trust_ctx=None, overrides=None, extra_ca_files=None):
    try: ip = resolve(host, overrides)
    except Exception as exc: return RawResult(False, str(exc))
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((ip, port), timeout) as sock, ctx.wrap_socket(sock, server_hostname=None if ip == host else host) as conn:
            der, version = conn.getpeercert(True), conn.version()
        chain_code, chain_message = None, None
        verify = ssl.create_default_context(cafile=certifi.where())
        for ca_file in extra_ca_files or []:
            path=Path(ca_file)
            if path.exists(): verify.load_verify_locations(cafile=str(path))
        verify.check_hostname = False
        try:
            with socket.create_connection((ip, port), timeout=timeout) as verify_sock, verify.wrap_socket(verify_sock, server_hostname=None if ip == host else host):
                chain_code = 0
        except ssl.SSLCertVerificationError as exc:
            chain_code = getattr(exc, "verify_code", 1); chain_message = str(exc)
        except OSError as exc:
            chain_code, chain_message = 1, str(exc)
        cert = x509.load_der_x509_certificate(der)
        def cn(name):
            vals = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME); return vals[0].value if vals else None
        san_dns, san_ip = [], []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san_dns, san_ip = ext.get_values_for_type(x509.DNSName), [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound: pass
        key = cert.public_key(); key_type = "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__
        return RawResult(True, resolved_ip=ip, leaf_pem=cert.public_bytes(serialization.Encoding.PEM).decode(), subject_cn=cn(cert.subject), san_dns=san_dns, san_ip=san_ip, issuer_cn=cn(cert.issuer), issuer_full=cert.issuer.rfc4514_string(), serial=str(cert.serial_number), thumbprint_sha1=hashlib.sha1(der).hexdigest().upper(), thumbprint_sha256=hashlib.sha256(der).hexdigest().upper(), not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc, key_type=key_type, key_size=getattr(key, "key_size", None), sig_hash=cert.signature_hash_algorithm.name, tls_version=version, chain_verify_code=chain_code, chain_verify_message=chain_message)
    except Exception as exc: return RawResult(False, f"TLS: {exc}", resolved_ip=ip)
