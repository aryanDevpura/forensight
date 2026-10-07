"""
Tests for Chain of Custody (Milestone 4).

Covers:
  1. Automatic custody record creation on evidence upload
  2. Retrieval via GET /api/custody/{evidence_id}
  3. Chronological ordering of custody records
  4. Invalid / nonexistent evidence_id returns 404
  5. Custody record fields are correct
  6. Multiple uploads produce independent custody chains
  7. Custody count reflected in /api/system/stats
"""

import hashlib
import io
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db

init_db()
client = TestClient(app)


def upload_test_evidence(
    filename: str = "custody_test.pcap",
    content: bytes = b"CUSTODY_TEST_ARTIFACT_BYTES",
    source_device: str = "workstation-custody-test",
    collector_id: str = "custody-test-collector",
):
    """Upload a test evidence file and return the response JSON."""
    response = client.post(
        "/api/evidence",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
        data={
            "source_device": source_device,
            "collector_id": collector_id,
            "description": "Chain of custody test artifact",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. Automatic custody record creation on evidence upload
# ---------------------------------------------------------------------------

def test_custody_record_created_on_upload():
    """Uploading evidence must automatically create an ACQUIRED custody entry."""
    evidence = upload_test_evidence(
        filename="auto_custody.log",
        content=b"AUTO_CUSTODY_TEST_CONTENT",
    )
    evidence_id = evidence["evidence_id"]

    response = client.get(f"/api/custody/{evidence_id}")
    assert response.status_code == 200, response.text

    chain = response.json()
    assert len(chain) >= 1, "Expected at least one custody record after upload"

    first = chain[0]
    assert first["evidence_id"] == evidence_id
    assert first["action"] == "ACQUIRED"
    assert first["actor"] == "custody-test-collector"
    assert first["timestamp"] is not None


# ---------------------------------------------------------------------------
# 2. Retrieval via GET /api/custody/{evidence_id}
# ---------------------------------------------------------------------------

def test_custody_retrieval_returns_correct_fields():
    """All expected fields must be present in custody records."""
    evidence = upload_test_evidence(
        filename="field_check.txt",
        content=b"FIELD_CHECK_CONTENT",
    )
    evidence_id = evidence["evidence_id"]

    response = client.get(f"/api/custody/{evidence_id}")
    assert response.status_code == 200

    chain = response.json()
    assert len(chain) >= 1

    record = chain[0]
    # Verify schema fields
    assert "id" in record
    assert "evidence_id" in record
    assert "action" in record
    assert "actor" in record
    assert "location" in record
    assert "notes" in record
    assert "timestamp" in record


# ---------------------------------------------------------------------------
# 3. Custody notes contain SHA-256 and file metadata
# ---------------------------------------------------------------------------

def test_custody_notes_contain_hash_and_metadata():
    """The automatic ACQUIRED custody note should mention the SHA-256 digest."""
    content = b"HASH_IN_NOTES_TEST_CONTENT"
    expected_hash = hashlib.sha256(content).hexdigest()

    evidence = upload_test_evidence(
        filename="hash_notes.csv",
        content=content,
    )
    evidence_id = evidence["evidence_id"]

    response = client.get(f"/api/custody/{evidence_id}")
    chain = response.json()
    first = chain[0]

    assert expected_hash in first["notes"], (
        f"Expected SHA-256 '{expected_hash}' in custody notes"
    )
    assert "hash_notes.csv" in first["notes"]
    assert str(len(content)) in first["notes"]


# ---------------------------------------------------------------------------
# 4. Invalid / nonexistent evidence_id returns 404
# ---------------------------------------------------------------------------

def test_custody_nonexistent_evidence_returns_404():
    """Requesting custody for a nonexistent evidence_id must return 404."""
    response = client.get("/api/custody/EVD-NONEXISTENT-FAKE99")
    assert response.status_code == 404, response.text
    detail = response.json()["detail"]
    assert "EVD-NONEXISTENT-FAKE99" in detail


def test_custody_empty_evidence_id_returns_404():
    """An empty-ish evidence_id string should return 404 (not crash)."""
    response = client.get("/api/custody/INVALID")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 5. Multiple uploads produce independent custody chains
# ---------------------------------------------------------------------------

def test_multiple_uploads_have_independent_chains():
    """Each uploaded evidence item must have its own isolated custody chain."""
    ev1 = upload_test_evidence(
        filename="independent_a.log",
        content=b"INDEPENDENT_A_DATA",
        collector_id="collector-A",
    )
    ev2 = upload_test_evidence(
        filename="independent_b.log",
        content=b"INDEPENDENT_B_DATA",
        collector_id="collector-B",
    )

    chain_a = client.get(f"/api/custody/{ev1['evidence_id']}").json()
    chain_b = client.get(f"/api/custody/{ev2['evidence_id']}").json()

    # Each chain should have exactly 1 record (the auto-generated ACQUIRED)
    assert len(chain_a) >= 1
    assert len(chain_b) >= 1

    # They must reference different evidence IDs
    assert chain_a[0]["evidence_id"] == ev1["evidence_id"]
    assert chain_b[0]["evidence_id"] == ev2["evidence_id"]
    assert chain_a[0]["evidence_id"] != chain_b[0]["evidence_id"]

    # Different collectors
    assert chain_a[0]["actor"] == "collector-A"
    assert chain_b[0]["actor"] == "collector-B"


# ---------------------------------------------------------------------------
# 6. Custody records are ordered chronologically (oldest first)
# ---------------------------------------------------------------------------

def test_custody_records_ordered_chronologically():
    """
    If an evidence item has multiple custody records, they must be
    returned oldest-first (ascending timestamp).
    """
    # Upload to create the initial ACQUIRED record
    evidence = upload_test_evidence(
        filename="ordering_test.pcap",
        content=b"ORDERING_TEST_DATA",
    )
    evidence_id = evidence["evidence_id"]

    # Manually insert additional custody records via the DB to test ordering
    from server.app.database.session import SessionLocal
    from server.app.models.custody import ChainOfCustody
    from datetime import datetime, timezone, timedelta

    db = SessionLocal()
    base_time = datetime.now(timezone.utc)
    try:
        for i, action in enumerate(["EXAMINED", "VERIFIED", "TRANSFERRED"]):
            record = ChainOfCustody(
                evidence_id=evidence_id,
                action=action,
                actor=f"examiner-{i}",
                location=f"lab-{i}",
                notes=f"Test action {action}",
                timestamp=base_time + timedelta(seconds=i + 1),
            )
            db.add(record)
        db.commit()
    finally:
        db.close()

    response = client.get(f"/api/custody/{evidence_id}")
    assert response.status_code == 200
    chain = response.json()

    # Should have at least 4 records: ACQUIRED + 3 manually inserted
    assert len(chain) >= 4

    # Verify chronological order
    for i in range(1, len(chain)):
        assert chain[i]["timestamp"] >= chain[i - 1]["timestamp"], (
            f"Custody records not in chronological order at index {i}"
        )

    # First should be ACQUIRED, rest in insertion order
    assert chain[0]["action"] == "ACQUIRED"
    actions = [r["action"] for r in chain[1:]]
    assert "EXAMINED" in actions
    assert "VERIFIED" in actions
    assert "TRANSFERRED" in actions


# ---------------------------------------------------------------------------
# 7. Custody count reflected in /api/system/stats
# ---------------------------------------------------------------------------

def test_custody_count_in_system_stats():
    """The system stats endpoint must reflect nonzero custody records."""
    response = client.get("/api/system/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["custody_records_count"] > 0, (
        "Expected custody_records_count > 0 after evidence uploads"
    )
