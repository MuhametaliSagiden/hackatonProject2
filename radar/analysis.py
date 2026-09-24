from datetime import UTC, datetime

from .checks import Finding
from .risk import score
from cryptography import x509
from ipaddress import ip_address


def analyze(raw, service, settings=None, now=None):
    now = now or datetime.now(UTC); settings = settings or {"info_days":60,"warning_days":30,"critical_days":14}
    if not raw.reachable: return {"status":"Unreachable","days_left":None,"findings":[Finding("UNREACHABLE", "high", f"Сервис недоступен: {raw.error}", "Проверьте доступность хоста и порта")],"risk_score":None,"risk_level":"N/A"}
    days = int((raw.not_after - now).total_seconds() // 86400)
    status = "Expired" if days < 0 else "Critical" if days <= settings.get("critical_days",14) else "Warning" if days <= settings.get("warning_days",30) else "Information" if days <= settings.get("info_days",60) else "OK"
    findings=[]
    if days < 0: findings.append(Finding("EXPIRED", "high", f"Срок действия сертификата истёк {abs(days)} дн. назад", "Срочно перевыпустите сертификат"))
    elif status != "OK": findings.append(Finding("EXPIRING", "high" if status == "Critical" else "medium", f"Сертификат истекает через {days} дн.", "Запланируйте перевыпуск сертификата"))
    if not service.owner: findings.append(Finding("NO_OWNER"))
    names = list(raw.san_dns or [])
    try:
        target_ip = ip_address(service.host)
        hostname_match = str(target_ip) in (raw.san_ip or [])
    except ValueError:
        names = names or ([raw.subject_cn] if raw.subject_cn else [])
        hostname_match = any(_hostname_matches(service.host, name) for name in names)
    if not hostname_match:
        findings.append(Finding("HOSTNAME_MISMATCH", "high", f"Имя {service.host} не совпадает с CN/SAN: {', '.join(names)}", "Перевыпустите сертификат с корректным именем в SAN"))
    try:
        cert = x509.load_pem_x509_certificate(raw.leaf_pem.encode())
        self_signed = cert.issuer == cert.subject and cert.verify_directly_issued_by(cert) is None
    except Exception:
        self_signed = False
    if self_signed: findings.append(Finding("SELF_SIGNED", "high", "Сертификат самоподписанный", "Замените сертификат на выпущенный доверенным центром сертификации"))
    if raw.chain_verify_code not in (None, 0) and not self_signed:
        findings.append(Finding("CHAIN_ERROR", "high", f"Ошибка цепочки доверия: {raw.chain_verify_message or raw.chain_verify_code}", "Установите на сервере полную цепочку сертификатов"))
    if raw.key_size and ((raw.key_type == "RSA" and raw.key_size < 2048) or (raw.key_type == "EC" and raw.key_size < 256)): findings.append(Finding("WEAK_KEY", "medium", f"Слабый ключ: {raw.key_size} бит", "Используйте ключ не менее RSA 2048 или ECDSA P-256"))
    if raw.sig_hash and raw.sig_hash.lower() in {"md5","sha1"}: findings.append(Finding("WEAK_SIGNATURE", "medium", f"Устаревший алгоритм подписи: {raw.sig_hash}", "Используйте SHA-256 или выше"))
    points, level = score(status, findings, service.criticality)
    return {"status":status,"days_left":days,"findings":findings,"risk_score":points,"risk_level":level,"hostname_match":hostname_match,"self_signed":self_signed,"weak_crypto":any(x.code.startswith("WEAK_") for x in findings)}

def _hostname_matches(host, pattern):
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern
