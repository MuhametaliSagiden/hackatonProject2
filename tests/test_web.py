from fastapi.testclient import TestClient
from radar.web.app import app

def test_health_and_targets_pages():
    client=TestClient(app)
    assert client.get("/health").json() == {"status":"ok"}
    assert "Цели" in client.get("/targets").text
