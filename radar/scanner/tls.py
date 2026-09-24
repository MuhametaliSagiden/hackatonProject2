import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .resolver import resolve


@dataclass
class RawResult:
    reachable: bool
    error: str | None = None
    resolved_ip: str | None = None
    leaf_pem: str | None = None
    subject_cn: str | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    issuer_cn: str | None = None
    issuer_full: str | None = None
    serial: str | None = None
    thumbprint_sha1: str | None = None
    thumbprint_sha256: str | None = None
    not_before: Any = None
    not_after: Any = None
    key_type: str | None = None
    key_size: int | None = None
    sig_hash: str | None = None
    tls_version: str | None = None
    chain_verify_code: int | None = None
    chain_verify_message: str | None = None


def classify_error(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "Таймаут соединения"
    if isinstance(exc, ConnectionRefusedError):
        return "В соединении отказано (порт закрыт или сервис недоступен)"
    if isinstance(exc, ConnectionResetError):
        return "Соединение сброшено удалённым узлом (Connection reset)"
    if isinstance(exc, socket.gaierror):
        return "DNS: не удалось разрешить имя"
    msg = str(exc)
    msg_lower = msg.lower()
    if "timed out" in msg_lower or "timeout" in msg_lower:
        return "Таймаут соединения"
    if "10061" in msg or "connection refused" in msg_lower or "111" in msg:
        return "В соединении отказано (порт закрыт или сервис недоступен)"
    if "10054" in msg or "connection reset" in msg_lower or "104" in msg:
        return "Соединение сброшено удалённым узлом (Connection reset)"
    return f"Ошибка соединения: {exc}"


def grab(
    host: str,
    port: int,
    timeout: float = 5.0,
    trust_ctx: Any = None,
    overrides: dict[str, str] | None = None,
    extra_ca_files: list[str] | None = None,
) -> RawResult:
    try:
        ip = resolve(host, overrides)
    except Exception as exc:
        return RawResult(False, error=str(exc))

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    server_hostname = None if is_ip else host

    # Connection 1: Get certificate regardless of trust
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:  # noqa: S110
            pass

        with (
            socket.create_connection((ip, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=server_hostname) as conn,
        ):
            der = conn.getpeercert(binary_form=True)
            version = conn.version()
    except Exception as exc:
        return RawResult(False, error=classify_error(exc), resolved_ip=ip)

    if not der:
        return RawResult(False, error="Сервер не предоставил сертификат", resolved_ip=ip)

    # Connection 2: Verify certificate chain
    chain_code: int | None = None
    chain_message: str | None = None
    try:
        verify = ssl.create_default_context(cafile=certifi.where())
        for ca_file in extra_ca_files or []:
            ca_path = Path(ca_file)
            if ca_path.exists():
                data = ca_path.read_bytes()
                if b"-----BEGIN" in data:
                    verify.load_verify_locations(cafile=str(ca_path))
                else:
                    verify.load_verify_locations(cadata=data)
        verify.check_hostname = False
        verify.verify_mode = ssl.CERT_REQUIRED

        with (
            socket.create_connection((ip, port), timeout=timeout) as verify_sock,
            verify.wrap_socket(verify_sock, server_hostname=server_hostname),
        ):
            chain_code = 0
            chain_message = "OK"
    except ssl.SSLCertVerificationError as exc:
        chain_code = getattr(exc, "verify_code", 1)
        chain_message = str(exc)
    except Exception as exc:
        chain_code = 1
        chain_message = str(exc)

    try:
        cert = x509.load_der_x509_certificate(der)

        def extract_cn(name: x509.Name) -> str | None:
            attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        san_dns: list[str] = []
        san_ip: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san_dns = [str(x) for x in ext.get_values_for_type(x509.DNSName)]
            san_ip = [str(x) for x in ext.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass

        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_type = "EC"
        else:
            key_type = type(key).__name__

        return RawResult(
            reachable=True,
            resolved_ip=ip,
            leaf_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            subject_cn=extract_cn(cert.subject),
            san_dns=san_dns,
            san_ip=san_ip,
            issuer_cn=extract_cn(cert.issuer),
            issuer_full=cert.issuer.rfc4514_string(),
            serial=str(cert.serial_number),
            thumbprint_sha1=hashlib.sha1(der).hexdigest().upper(),
            thumbprint_sha256=hashlib.sha256(der).hexdigest().upper(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            key_type=key_type,
            key_size=getattr(key, "key_size", None),
            sig_hash=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
            tls_version=version,
            chain_verify_code=chain_code,
            chain_verify_message=chain_message,
        )
    except Exception as exc:
        return RawResult(False, error=f"Ошибка разбора сертификата: {exc}", resolved_ip=ip)
