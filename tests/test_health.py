from fastapi.testclient import TestClient
from server.app.main import app
from server.app.database.session import init_db

# Initialize database schema for tests
init_db()

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "ForenSight" in data["system"]


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "ForenSight Investigation Server"
    assert data["database"] == "connected"
    assert "storage" in data
    assert data["storage"]["evidence_dir"] == "available"
    assert data["storage"]["reports_dir"] == "available"


def test_system_stats_endpoint():
    response = client.get("/api/system/stats")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["evidence_count"], int)
    assert data["evidence_count"] >= 0
    assert isinstance(data["findings_count"], int)
    assert isinstance(data["events_count"], int)
    assert data["events_count"] >= 0
    assert isinstance(data["custody_records_count"], int)
    assert data["custody_records_count"] >= 0
    assert data["benchmark_runs_count"] == 0
