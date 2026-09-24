import logging
import os
from typing import Any

from sqlmodel import select

from ..audit import audit
from ..config import load_config
from ..db import session
from ..models import CertResult, NotificationLog, Service, Setting
from .console import ConsoleChannel
from .email import EmailChannel
from .telegram import TelegramChannel

logger = logging.getLogger("radar")


def get_active_channels(config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or load_config()
    notify = cfg.get("notify", {})
    channels: dict[str, Any] = {"console": ConsoleChannel()}

    if notify.get("email_enabled") and notify.get("smtp_host"):
        channels["email"] = EmailChannel(
            host=notify.get("smtp_host", ""),
            port=int(notify.get("smtp_port", 25)),
            sender=notify.get("smtp_from", "radar@localhost"),
            recipients=notify.get("email_to", []),
            user=os.getenv("SMTP_USER"),
            password=os.getenv("SMTP_PASSWORD"),
        )

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if notify.get("telegram_enabled") and bot_token and chat_id:
        channels["telegram"] = TelegramChannel(bot_token, chat_id)

    return channels


def notify_after_scan(scan_id: int, thresholds: tuple[int, ...] = (60, 30, 14, 7, 1)) -> int:
    cfg = load_config()
    configured_thresholds = cfg.get("notify_thresholds", thresholds)

    with session() as db:
        stored = db.get(Setting, "notify_thresholds")
        if stored:
            val = stored.value
            if isinstance(val, list):
                configured_thresholds = val
            elif isinstance(val, str):
                configured_thresholds = [int(x.strip()) for x in val.split(",") if x.strip()]

        results = list(db.exec(select(CertResult).where(CertResult.scan_id == scan_id)))
        services = {s.id: s for s in db.exec(select(Service))}

    channels = get_active_channels(cfg)
    total_sent = 0

    for res in results:
        if not res.reachable or not res.thumbprint_sha1 or res.days_left is None:
            continue

        days = res.days_left
        if days < 0:
            threshold = 0
        else:
            candidates = [t for t in sorted(configured_thresholds) if days <= t]
            if not candidates:
                continue
            threshold = candidates[0]

        srv = services.get(res.service_id)
        if not srv:
            continue

        findings = res.findings if isinstance(res.findings, list) else []
        recommendation = ""
        for f in findings:
            if isinstance(f, dict) and f.get("recommendation"):
                recommendation = f["recommendation"]
                break
        if not recommendation:
            recommendation = (
                "Срочно перевыпустите сертификат"
                if threshold == 0
                else "Запланируйте перевыпуск и замену сертификата до даты окончания."
            )

        svc_name_str = srv.service_name or "без имени"
        owner_str = srv.owner or "не назначен"

        if threshold == 0:
            status_text = f"ИСТЁК {abs(days)} дн. назад (порог {threshold})"
        else:
            status_text = f"истекает через {days} дн. (порог {threshold})"

        message = (
            f"Certificate Radar: сертификат {srv.host}:{srv.port} ({svc_name_str}) {status_text}. "
            f"Владелец: {owner_str}. Risk {res.risk_score} ({res.risk_level}). "
            f"Рекомендация: {recommendation}"
        )

        for channel_name, channel in channels.items():
            with session() as db:
                existing = db.exec(
                    select(NotificationLog).where(
                        NotificationLog.thumbprint_sha1 == res.thumbprint_sha1,
                        NotificationLog.threshold == threshold,
                        NotificationLog.channel == channel_name,
                        NotificationLog.success == True,
                    )
                ).first()
                if existing:
                    continue

                success = True
                try:
                    success = channel.send(message)
                except Exception as exc:
                    success = False
                    logger.error("Ошибка отправки через канал %s: %s", channel_name, exc)

                log_entry = NotificationLog(
                    service_id=srv.id,
                    thumbprint_sha1=res.thumbprint_sha1,
                    threshold=threshold,
                    channel=channel_name,
                    success=success,
                    message=message,
                )
                db.add(log_entry)
                try:
                    db.commit()
                except Exception:
                    db.rollback()

                if success:
                    total_sent += 1

                audit(
                    "NOTIFICATION_SENT",
                    {
                        "scan_id": scan_id,
                        "service_id": srv.id,
                        "host": srv.host,
                        "channel": channel_name,
                        "threshold": threshold,
                        "success": success,
                    },
                )

    return total_sent


def send_test(channels: list[str] | None = None) -> dict[str, bool]:
    cfg = load_config()
    available_channels = get_active_channels(cfg)

    target_channels = (
        {k: available_channels[k] for k in channels if k in available_channels}
        if channels is not None
        else available_channels
    )

    message = "Certificate Radar: тестовое уведомление"
    results: dict[str, bool] = {}

    for name, channel in target_channels.items():
        try:
            ok = channel.send(message)
            results[name] = bool(ok)
        except Exception as exc:
            logger.error("Ошибка тестового уведомления %s: %s", name, exc)
            results[name] = False

    audit("NOTIFICATION_TEST", results)
    return results
