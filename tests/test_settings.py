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
