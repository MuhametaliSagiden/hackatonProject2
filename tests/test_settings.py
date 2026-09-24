from fastapi.testclient import TestClient
from radar.web.app import app


def test_invalid_threshold_order_is_rejected():
    response = TestClient(app).post(
        "/settings",
        data={
            "info_days": 10,
            "warning_days": 20,
            "critical_days": 5,
            "notify_thresholds": "60,30",
            "schedule_hours": 0,
        },
    )
    assert response.status_code == 400
    assert "info &gt; warning" in response.text or "info > warning" in response.text


def test_schedule_is_updated_without_restart(monkeypatch):
    updates = []
    monkeypatch.setattr("radar.web.app.update_scheduler", lambda scheduler, hours: updates.append(hours))
    monkeypatch.setattr("radar.services.recompute_latest", lambda: 0)
    monkeypatch.setattr("radar.services.audit", lambda *args, **kwargs: None)

    response = TestClient(app).post(
        "/settings",
        data={
            "info_days": 60,
            "warning_days": 30,
            "critical_days": 14,
            "notify_thresholds": "60,30,14,7,1",
            "schedule_hours": 6,
        },
    )

    assert response.status_code == 200
    assert updates == [6]
    assert "расписание обновлено" in response.text
