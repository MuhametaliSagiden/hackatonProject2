from fastapi.testclient import TestClient
from uuid import uuid4
from radar.web.app import app


def test_health_and_targets_pages():
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    targets = client.get("/targets")
    assert targets.status_code == 200
    assert "Цели" in targets.text
    assert 'action="/targets/upload"' in targets.text
    assert 'name="target_text"' in targets.text
    assert 'action="/scans/start"' in targets.text
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


def test_certificate_filters_include_owner_issuer_and_sort_controls():
    client = TestClient(app)
    response = client.get("/certificates?owner=owner@example&issuer=Example%20CA&sort=risk&dir=desc")
    assert response.status_code == 200
    assert 'name="owner"' in response.text
    assert 'name="issuer"' in response.text
    assert 'name="risk_level"' in response.text
    assert 'name="days_max"' in response.text
    assert "CSV" in response.text
    assert "sort=owner&dir=" in response.text
    assert "sort=days_left&dir=" in response.text


def test_api_settings_and_results_endpoints():
    client = TestClient(app)
    assert client.get("/api/settings").status_code == 200
    assert client.get("/api/results").status_code == 200
    rejected = client.put(
        "/api/settings",
        json={"info_days": 10, "warning_days": 20, "critical_days": 5, "notify_thresholds": [60, 30], "schedule_hours": 0},
    )
    assert rejected.status_code == 400
    assert client.get("/api/export?format=csv").status_code == 200


def test_dashboard_metrics_and_api():
    client = TestClient(app)
    dash_api = client.get("/api/dashboard")
    assert dash_api.status_code == 200
    payload = dash_api.json()
    assert "health_score" in payload
    assert "findings_summary" in payload
    assert "reachable_count" in payload
    assert "unreachable_count" in payload
    assert "reachability_rate" in payload
    root_html = client.get("/")
    assert root_html.status_code == 200
    assert "Обзор сертификатов" in root_html.text
