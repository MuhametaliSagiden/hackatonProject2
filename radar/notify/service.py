import logging
import os
from .email import EmailChannel
from .telegram import TelegramChannel
from sqlmodel import select
from ..db import session
from ..models import CertResult, NotificationLog, Service, Setting
from ..audit import audit
from ..config import load_config
from .console import ConsoleChannel

def notify_after_scan(scan_id, thresholds=(60, 30, 14, 7, 1)):
    cfg=load_config(); thresholds=cfg.get("notify_thresholds",thresholds); notify=cfg.get("notify",{})
    channels={"console":ConsoleChannel()}
    if notify.get("email_enabled"):
        channels["email"]=EmailChannel(notify.get("smtp_host"),int(notify.get("smtp_port",25)),notify.get("smtp_from","radar@localhost"),notify.get("email_to",[]))
    if notify.get("telegram_enabled") and os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
        channels["telegram"]=TelegramChannel(os.getenv("TELEGRAM_BOT_TOKEN"),os.getenv("TELEGRAM_CHAT_ID"))
    db=session(); stored_thresholds=db.get(Setting,"notify_thresholds")
    if stored_thresholds: thresholds=[int(x) for x in stored_thresholds.value.split(",")]
    results=list(db.exec(select(CertResult).where(CertResult.scan_id == scan_id))); services={s.id:s for s in db.exec(select(Service))}; sent=0
    for result in results:
        if not result.reachable or not result.thumbprint_sha1 or result.days_left is None: continue
        threshold=0 if result.days_left < 0 else next((x for x in sorted(thresholds) if result.days_left <= x), None)
        if threshold is None: continue
        service=services[result.service_id]
        message=(f"Certificate Radar: сертификат {service.host}:{service.port} истёк {abs(result.days_left)} дн. назад" if threshold == 0 else f"Certificate Radar: сертификат {service.host}:{service.port} истекает через {result.days_left} дн.")
        message += f" Risk {result.risk_score} ({result.risk_level}). Владелец: {service.owner or 'не назначен'}."
        for channel_name,channel in channels.items():
            existing=db.exec(select(NotificationLog).where(NotificationLog.thumbprint_sha1 == result.thumbprint_sha1, NotificationLog.threshold == threshold, NotificationLog.channel == channel_name, NotificationLog.success == True)).first()
            if existing: continue
            try: success=channel.send(message)
            except Exception as exc: success=False; logging.getLogger("radar").error("Ошибка канала %s: %s",channel_name,exc)
            db.add(NotificationLog(service_id=service.id,thumbprint_sha1=result.thumbprint_sha1,threshold=threshold,channel=channel_name,message=message,success=success)); sent += int(success)
    db.commit(); db.close()
    if sent: audit("NOTIFICATION_SENT", {"scan_id":scan_id,"count":sent})
    return sent

def send_test(channels=None):
    channels=channels or ["console"]; message="Certificate Radar: тестовое уведомление"; results={"console": True}
    if "email" in channels:
        try: results["email"]=EmailChannel(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT", "25")), os.getenv("SMTP_FROM", "radar@localhost"), os.getenv("SMTP_TO", "").split(",")).send(message)
        except Exception as exc: logging.getLogger("radar").error("Ошибка email: %s", exc); results["email"]=False
    if "telegram" in channels and os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
        try: results["telegram"]=TelegramChannel(os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")).send(message)
        except Exception as exc: logging.getLogger("radar").error("Ошибка Telegram: %s", exc); results["telegram"]=False
    audit("NOTIFICATION_TEST", results); return results
