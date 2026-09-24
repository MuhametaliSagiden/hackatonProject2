import logging
from sqlmodel import select
from ..db import session
from ..models import CertResult, NotificationLog, Service

def notify_after_scan(scan_id, thresholds=(60, 30, 14, 7, 1)):
    db=session(); results=list(db.exec(select(CertResult).where(CertResult.scan_id == scan_id))); services={s.id:s for s in db.exec(select(Service))}; sent=0
    for result in results:
        if not result.reachable or not result.thumbprint_sha1 or result.days_left is None: continue
        threshold=0 if result.days_left < 0 else next((x for x in sorted(thresholds) if result.days_left <= x), None)
        if threshold is None: continue
        service=services[result.service_id]; existing=db.exec(select(NotificationLog).where(NotificationLog.thumbprint_sha1 == result.thumbprint_sha1, NotificationLog.threshold == threshold, NotificationLog.channel == "console", NotificationLog.success == True)).first()
        if existing: continue
        message=(f"Certificate Radar: сертификат {service.host}:{service.port} истёк {abs(result.days_left)} дн. назад" if threshold == 0 else f"Certificate Radar: сертификат {service.host}:{service.port} истекает через {result.days_left} дн.")
        message += f" Risk {result.risk_score} ({result.risk_level}). Владелец: {service.owner or 'не назначен'}."
        logging.getLogger("radar").warning(message); db.add(NotificationLog(service_id=service.id, thumbprint_sha1=result.thumbprint_sha1, threshold=threshold, channel="console", message=message)); sent += 1
    db.commit(); db.close(); return sent
