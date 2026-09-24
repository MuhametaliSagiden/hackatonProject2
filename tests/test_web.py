from fastapi.testclient import TestClient
from uuid import uuid4
from radar.web.app import app


def test_health_and_targets_pages():
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    assert "Цели" in client.get("/targets").text
    assert client.get("/static/bootstrap.min.css").status_code == 200
    assert "Обзор сертификатов" in client.get("/").text


def test_file_upload_and_missing_scan_page():
    client = TestClient(app)
    host = f"{uuid4().hex}.example"
    response = client.post(
        "/targets/upload",
        files={"file": ("targets.csv", f"target,owner\n{host},admin@example\n", "text/csv")},
    )
    assert response.status_code == 200
    assert "Добавлено: 1" in response.text
    item = next(x for x in client.get("/api/services").json() if x["host"] == host)
    updated = client.post(
        f"/targets/{item['id']}",
        data={"owner": "new-owner@example", "criticality": "high"},
        follow_redirects=False,
    )
    assert updated.status_code == 303
    saved = next(x for x in client.get("/api/services").json() if x["id"] == item["id"])
    assert saved["owner"] == "new-owner@example"
    assert saved["criticality"] == "high"
    assert client.get("/scans/999999999").status_code == 404


def test_import_and_settings_use_jinja_pages():
    client = TestClient(app)
    imported = client.post(
        "/targets/import", data={"target_text": "valid.example\nvalid.example\nnot a host!!"}
    )
    assert imported.status_code == 200
    assert "Результат импорта" in imported.text
    assert "<a href='/targets'>" not in imported.text

    saved = client.post(
        "/settings",
        data={
            "info_days": 60,
            "warning_days": 30,
            "critical_days": 14,
            "notify_thresholds": "60,30,14,7,1",
            "schedule_hours": 0,
        },
    )
    assert saved.status_code == 200
    assert "Настройки сохранены" in saved.text
    assert "<p>Настройки сохранены" not in saved.text
