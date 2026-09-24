from datetime import UTC, datetime

from .checks import Finding
from .risk import score
from ipaddress import ip_address
from .checks.expiry import status_for_days
from .checks.hostname import matches as hostname_matches
from .checks.selfsigned import is_self_signed
from .checks.crypto import weak_key, weak_signature
from .checks.owner import missing_owner


def analyze(raw, service, settings=None, now=None):
    now = now or datetime.now(UTC); settings = settings or {"info_days":60,"warning_days":30,"critical_days":14}
    if not raw.reachable: return {"status":"Unreachable","days_left":None,"findings":[Finding("UNREACHABLE", "high", f"Сервис недоступен: {raw.error}", "Проверьте доступность хоста и порта")],"risk_score":None,"risk_level":"N/A"}
    days = int((raw.not_after - now).total_seconds() // 86400)
    status = status_for_days(days,settings)
    findings=[]
    if days < 0: findings.append(Finding("EXPIRED", "high", f"Срок действия сертификата истёк {abs(days)} дн. назад", "Срочно перевыпустите сертификат"))
    elif status != "OK": findings.append(Finding("EXPIRING", "high" if status == "Critical" else "medium", f"Сертификат истекает через {days} дн.", "Запланируйте перевыпуск сертификата"))
    if missing_owner(service.owner): findings.append(Finding("NO_OWNER"))
    names = list(raw.san_dns or [])
    try:
        target_ip = ip_address(service.host)
        hostname_match = str(target_ip) in (raw.san_ip or [])
    except ValueError:
        names = names or ([raw.subject_cn] if raw.subject_cn else [])
        hostname_match = any(hostname_matches(service.host, name) for name in names)
    if not hostname_match:
        findings.append(Finding("HOSTNAME_MISMATCH", "high", f"Имя {service.host} не совпадает с CN/SAN: {', '.join(names)}", "Перевыпустите сертификат с корректным именем в SAN"))
    self_signed = is_self_signed(raw.leaf_pem)
    if self_signed: findings.append(Finding("SELF_SIGNED", "high", "Сертификат самоподписанный", "Замените сертификат на выпущенный доверенным центром сертификации"))
    if raw.chain_verify_code not in (None, 0, 9, 10) and not self_signed:
        findings.append(Finding("CHAIN_ERROR", "high", f"Ошибка цепочки доверия: {raw.chain_verify_message or raw.chain_verify_code}", "Установите на сервере полную цепочку сертификатов"))
    if weak_key(raw.key_type,raw.key_size): findings.append(Finding("WEAK_KEY", "medium", f"Слабый ключ: {raw.key_size} бит", "Используйте ключ не менее RSA 2048 или ECDSA P-256"))
    if weak_signature(raw.sig_hash): findings.append(Finding("WEAK_SIGNATURE", "medium", f"Устаревший алгоритм подписи: {raw.sig_hash}", "Используйте SHA-256 или выше"))
    points, level = score(status, findings, service.criticality, days)
    return {"status":status,"days_left":days,"findings":findings,"risk_score":points,"risk_level":level,"hostname_match":hostname_match,"self_signed":self_signed,"weak_crypto":any(x.code.startswith("WEAK_") for x in findings)}

_hostname_matches = hostname_matches
