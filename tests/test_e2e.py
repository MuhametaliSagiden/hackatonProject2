from time import monotonic
from fastapi.testclient import TestClient
from radar.targets.parser import parse_text
from radar.web.app import app

def test_web_navigation_and_exports():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/targets").status_code == 200
        assert client.get("/certificates").status_code == 200
        assert client.get("/scans").status_code == 200
        assert client.get("/audit").status_code == 200
        for endpoint in ["/api/dashboard","/api/services","/api/scans","/api/certificates","/api/audit","/api/notifications"]:
            assert client.get(endpoint).status_code == 200
        csv=client.get("/export?format=csv")
        assert csv.status_code == 200
        assert "text/csv" in csv.headers["content-type"]
        assert client.get("/export?format=xlsx").content.startswith(b"PK")
        assert "<table>" in client.get("/export?format=html").text

def test_cidr_limit_is_fast_and_bounded():
    started=monotonic(); report=parse_text("127.0.0.0/24",max_cidr_hosts=256)
    assert len(report.services) == 254
    assert monotonic()-started < 1
    rejected=parse_text("10.0.0.0/16",max_cidr_hosts=256)
    assert len(rejected.invalid) == 1
