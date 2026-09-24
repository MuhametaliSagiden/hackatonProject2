from apscheduler.schedulers.background import BackgroundScheduler
from .services import run_scan

def start_scheduler(hours=0):
    scheduler=BackgroundScheduler()
    if hours and hours > 0: scheduler.add_job(lambda: run_scan("schedule"), "interval", hours=hours, id="radar-scan", replace_existing=True)
    scheduler.start(); return scheduler
