import io
import hashlib
from pathlib import Path
from fastapi.testclient import TestClient
from server.app.main import app
from server.app.database.session import init_db

# Ensure test DB is initialized
init_db()

client = TestClient(app)


def test_successful_evidence_upload_and_sha256():
    # Known test vector with deterministic SHA-256
    known_content = b"FORENSIC_EVIDENCE_SAMPLE_PACKET_DATA_2026_TEST_VECTOR_12345"
    expected_sha256 = hashlib.sha256(known_content).hexdigest()

    file_tuple = ("network_traffic.pcap", io.BytesIO(known_content), "application/octet-stream")
    form_data = {
        "source_device": "sensor-alpha-01",
        "collector_id": "collector-node-01",
        "description": "Perimeter network packet capture test",
    }

    response = client.post(
        "/api/evidence",
        files={"file": file_tuple},
        data=form_data,
    )

    assert response.status_code == 201, response.text
    data = response.json()

    # Validate generated attributes
    assert "evidence_id" in data
    assert data["evidence_id"].startswith("EVD-")
    assert data["file_name"] == "network_traffic.pcap"
    assert data["evidence_type"] == "PCAP"
    assert data["source_device"] == "sensor-alpha-01"
    assert data["collector_id"] == "collector-node-01"
    assert data["file_size_bytes"] == len(known_content)
    assert data["status"] == "ACQUIRED"

    # Independently verify the calculated SHA-256
    assert data["sha256_hash"] == expected_sha256

    # Verify physical file existence and on-disk cryptographic integrity
    disk_path = Path(data["file_path"])
    assert disk_path.exists(), f"Evidence file not found on disk at {disk_path}"
    with open(disk_path, "rb") as f:
        disk_content = f.read()
    assert disk_content == known_content
    assert hashlib.sha256(disk_content).hexdigest() == expected_sha256


def test_evidence_retrieval_endpoint():
    response = client.get("/api/evidence")
    assert response.status_code == 200
    records = response.json()
    assert isinstance(records, list)
    assert len(records) >= 1

    first_record = records[0]
    assert "evidence_id" in first_record
    assert "sha256_hash" in first_record
    assert first_record["status"] == "ACQUIRED"


def test_unsupported_file_type_rejection():
    # .exe is disallowed
    bad_content = b"DISALLOWED_EXECUTABLE_CONTENT"
    file_tuple = ("suspicious_tool.exe", io.BytesIO(bad_content), "application/octet-stream")

    response = client.post(
        "/api/evidence",
        files={"file": file_tuple},
        data={"source_device": "workstation-01"},
    )

    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "Unsupported file type '.exe'" in detail


def test_path_traversal_sanitization():
    content = b"TRAVERSAL_TEST_LOG_DATA"
    expected_hash = hashlib.sha256(content).hexdigest()
    # Attempt filename with traversal sequences
    file_tuple = ("../../../../root_compromise.log", io.BytesIO(content), "text/plain")

    response = client.post(
        "/api/evidence",
        files={"file": file_tuple},
        data={"source_device": "workstation-02"},
    )

    assert response.status_code == 201
    data = response.json()

    # The file_name should be sanitized to just the basename
    assert data["file_name"] == "root_compromise.log"
    assert data["sha256_hash"] == expected_hash

    # Path on disk must reside inside storage/evidence
    disk_path = Path(data["file_path"]).resolve()
    assert ".." not in str(disk_path)
    assert disk_path.exists()
