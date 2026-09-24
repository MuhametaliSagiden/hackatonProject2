import logging
from apscheduler.schedulers.background import BackgroundScheduler
from .services import run_scan

logger = logging.getLogger("radar")


def start_scheduler(hours: int = 0) -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    if hours and hours > 0:
        scheduler.add_job(
            lambda: run_scan("schedule"),
            "interval",
            hours=hours,
            id="radar-scan",
            replace_existing=True,
        )
    scheduler.start()
    return scheduler


def update_scheduler(scheduler: BackgroundScheduler | None, hours: int):
    if not scheduler:
        return
    try:
        if hours and hours > 0:
            scheduler.add_job(
                lambda: run_scan("schedule"),
                "interval",
                hours=hours,
                id="radar-scan",
                replace_existing=True,
            )
            logger.info("Расписание сканирования обновлено: каждые %d ч.", hours)
        else:
            if scheduler.get_job("radar-scan"):
                scheduler.remove_job("radar-scan")
            logger.info("Расписание сканирования отключено.")
    except Exception as exc:
        logger.error("Ошибка обновления расписания: %s", exc)
