from fastapi.testclient import TestClient
from uuid import uuid4
from radar.web.app import app

def test_health_and_targets_pages():
    client=TestClient(app)
    assert client.get("/health").json() == {"status":"ok"}
    assert "Цели" in client.get("/targets").text

def test_file_upload_and_missing_scan_page():
    client=TestClient(app); host=f"{uuid4().hex}.example"
    response=client.post("/targets/upload",files={"file":("targets.csv",f"target,owner\n{host},admin@example\n","text/csv")})
    assert response.status_code == 200
    assert "Добавлено: 1" in response.text
    assert client.get("/scans/999999999").status_code == 404
