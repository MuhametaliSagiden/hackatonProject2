import logging
import os
from .email import EmailChannel
from .telegram import TelegramChannel
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

def send_test(channels=None):
    channels=channels or ["console"]; message="Certificate Radar: тестовое уведомление"; results={"console": True}
    if "email" in channels:
        try: results["email"]=EmailChannel(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT", "25")), os.getenv("SMTP_FROM", "radar@localhost"), os.getenv("SMTP_TO", "").split(",")).send(message)
        except Exception as exc: logging.getLogger("radar").error("Ошибка email: %s", exc); results["email"]=False
    if "telegram" in channels and os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
        try: results["telegram"]=TelegramChannel(os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")).send(message)
        except Exception as exc: logging.getLogger("radar").error("Ошибка Telegram: %s", exc); results["telegram"]=False
    return results
