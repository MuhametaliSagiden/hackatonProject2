from radar.notify.service import notify_after_scan
from radar.models import NotificationLog

def test_notification_module_has_public_entrypoint():
    assert callable(notify_after_scan)
    assert NotificationLog.__tablename__ == "notificationlog"
