from dataclasses import dataclass
from datetime import timezone
import hashlib, json, socket, ssl
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
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
        cert = x509.load_der_x509_certificate(der)
        def cn(name):
            vals = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME); return vals[0].value if vals else None
        san_dns, san_ip = [], []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san_dns, san_ip = ext.get_values_for_type(x509.DNSName), [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound: pass
        key = cert.public_key(); key_type = "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__
        return RawResult(True, resolved_ip=ip, leaf_pem=cert.public_bytes(serialization.Encoding.PEM).decode(), subject_cn=cn(cert.subject), san_dns=san_dns, san_ip=san_ip, issuer_cn=cn(cert.issuer), issuer_full=cert.issuer.rfc4514_string(), serial=str(cert.serial_number), thumbprint_sha1=hashlib.sha1(der).hexdigest().upper(), thumbprint_sha256=hashlib.sha256(der).hexdigest().upper(), not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc, key_type=key_type, key_size=getattr(key, "key_size", None), sig_hash=cert.signature_hash_algorithm.name, tls_version=version)
    except Exception as exc: return RawResult(False, f"TLS: {exc}", resolved_ip=ip)
