from datetime import UTC, datetime

from .checks import Finding
from .risk import score


def analyze(raw, service, settings=None, now=None):
    now = now or datetime.now(UTC); settings = settings or {"info_days":60,"warning_days":30,"critical_days":14}
    if not raw.reachable: return {"status":"Unreachable","days_left":None,"findings":[Finding("UNREACHABLE", "high", f"Сервис недоступен: {raw.error}", "Проверьте доступность хоста и порта")],"risk_score":None,"risk_level":"N/A"}
    days = int((raw.not_after - now).total_seconds() // 86400)
    status = "Expired" if days < 0 else "Critical" if days <= settings.get("critical_days",14) else "Warning" if days <= settings.get("warning_days",30) else "Information" if days <= settings.get("info_days",60) else "OK"
    findings=[]
    if days < 0: findings.append(Finding("EXPIRED", "high", f"Срок действия сертификата истёк {abs(days)} дн. назад", "Срочно перевыпустите сертификат"))
    elif status != "OK": findings.append(Finding("EXPIRING", "high" if status == "Critical" else "medium", f"Сертификат истекает через {days} дн.", "Запланируйте перевыпуск сертификата"))
    if not service.owner: findings.append(Finding("NO_OWNER"))
    if raw.key_size and ((raw.key_type == "RSA" and raw.key_size < 2048) or (raw.key_type == "EC" and raw.key_size < 256)): findings.append(Finding("WEAK_KEY", "medium", f"Слабый ключ: {raw.key_size} бит", "Используйте ключ не менее RSA 2048 или ECDSA P-256"))
    if raw.sig_hash and raw.sig_hash.lower() in {"md5","sha1"}: findings.append(Finding("WEAK_SIGNATURE", "medium", f"Устаревший алгоритм подписи: {raw.sig_hash}", "Используйте SHA-256 или выше"))
    points, level = score(status, findings, service.criticality)
    return {"status":status,"days_left":days,"findings":findings,"risk_score":points,"risk_level":level}
