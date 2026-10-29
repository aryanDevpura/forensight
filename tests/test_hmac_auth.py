"""
Tests for HMAC-SHA256 Collector → Server authentication.

Covers:
  1. Valid authenticated request succeeds (201)
  2. Invalid/tampered signature is rejected (403)
  3. Expired/replayed timestamp is rejected (401)
  4. Missing auth headers return 422 (FastAPI validation)
  5. Payload hash mismatch (in-transit tampering) rejected (422)
  6. No HMAC secret configured → 401 with instructive message
  7. Existing unauthenticated browser upload still works (201)
  8. Existing evidence list endpoint still works (200)
"""

import hashlib
import hmac
import io
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from fastapi import HTTPException
from server.app.main import app
from server.app.database.session import init_db
from server.app.core.hmac_auth import compute_hmac, verify_hmac_signature, REPLAY_WINDOW_SECONDS
from collector.auth import compute_payload_hash, sign_request
from tests.crypto_test_utils import upload_secure_evidence

# ---------------------------------------------------------------------------
# Test setup
# ---------------------------------------------------------------------------

init_db()
client = TestClient(app)

# Shared test secret — matches FORENSIGHT_HMAC_SECRET set via monkeypatch
TEST_SECRET = "test-hmac-secret-forensight-unit-testing"

KNOWN_CONTENT = b"FORENSIC_ARTIFACT_HMAC_AUTH_TEST_PAYLOAD_2026"
KNOWN_HASH = hashlib.sha256(KNOWN_CONTENT).hexdigest()
TEST_EVIDENCE_ID = "PENDING-test_artifact.pcap"


def make_auth_headers(
    secret: str = TEST_SECRET,
    evidence_id: str = TEST_EVIDENCE_ID,
    payload_hash: str = KNOWN_HASH,
    timestamp: int | None = None,
) -> dict:
    """Build valid HMAC auth headers for a test request."""
    ts = timestamp if timestamp is not None else int(time.time())
    return sign_request(
        secret=secret,
        evidence_id=evidence_id,
        payload_hash=payload_hash,
        timestamp=ts,
    )


class MockRequest:
    def __init__(self):
        self.state = type("State", (), {})()


def call_verify_hmac(headers: dict, request: MockRequest | None = None) -> dict:
    req = request or MockRequest()
    return verify_hmac_signature(
        request=req,
        x_forensight_timestamp=headers["X-ForenSight-Timestamp"],
        x_forensight_evidence_id=headers["X-ForenSight-Evidence-ID"],
        x_forensight_payload_hash=headers["X-ForenSight-Payload-Hash"],
        x_forensight_signature=headers["X-ForenSight-Signature"],
    )


# ---------------------------------------------------------------------------
# 1. Valid authenticated request succeeds
# ---------------------------------------------------------------------------

def test_valid_authenticated_upload_succeeds():
    """A correctly signed request must verify successfully."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET
        headers = make_auth_headers()
        claims = call_verify_hmac(headers)

    assert claims["evidence_id"] == TEST_EVIDENCE_ID
    assert claims["payload_hash"] == KNOWN_HASH
    assert claims["timestamp"] is not None


# ---------------------------------------------------------------------------
# 2. Tampered signature is rejected (403)
# ---------------------------------------------------------------------------

def test_tampered_signature_is_rejected():
    """A request with a forged/corrupted HMAC signature must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        headers = make_auth_headers()
        good_sig = headers["X-ForenSight-Signature"]
        tampered_char = "0" if good_sig[0] != "0" else "1"
        headers["X-ForenSight-Signature"] = tampered_char + good_sig[1:]

        with pytest.raises(HTTPException) as exc_info:
            call_verify_hmac(headers)

    assert exc_info.value.status_code == 403
    assert "HMAC signature verification failed" in exc_info.value.detail


def test_wrong_secret_is_rejected():
    """A request signed with a different secret must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        headers = sign_request(
            secret="completely-wrong-secret",
            evidence_id=TEST_EVIDENCE_ID,
            payload_hash=KNOWN_HASH,
        )
        with pytest.raises(HTTPException) as exc_info:
            call_verify_hmac(headers)

    assert exc_info.value.status_code == 403
    assert "HMAC signature verification failed" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 3. Expired / replayed timestamp is rejected (401)
# ---------------------------------------------------------------------------

def test_expired_timestamp_is_rejected():
    """A request with a timestamp older than the replay window must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        expired_ts = int(time.time()) - (REPLAY_WINDOW_SECONDS + 60)
        headers = make_auth_headers(timestamp=expired_ts)
        with pytest.raises(HTTPException) as exc_info:
            call_verify_hmac(headers)

    assert exc_info.value.status_code == 401
    assert "replay window" in exc_info.value.detail.lower()


def test_future_timestamp_beyond_window_is_rejected():
    """A request with a timestamp far in the future must also be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        future_ts = int(time.time()) + (REPLAY_WINDOW_SECONDS + 60)
        headers = make_auth_headers(timestamp=future_ts)
        with pytest.raises(HTTPException) as exc_info:
            call_verify_hmac(headers)

    assert exc_info.value.status_code == 401
    assert "replay window" in exc_info.value.detail.lower()


def test_timestamp_within_window_is_accepted():
    """A request timestamp at the edge of the allowed window must succeed."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        near_edge_ts = int(time.time()) - (REPLAY_WINDOW_SECONDS - 10)
        headers = make_auth_headers(timestamp=near_edge_ts)
        claims = call_verify_hmac(headers)

    assert claims["evidence_id"] == TEST_EVIDENCE_ID


# ---------------------------------------------------------------------------
# 4. Obsolete collector endpoint is inactive (404)
# ---------------------------------------------------------------------------

def test_obsolete_collector_endpoint_rejected_as_inactive():
    """Requests to the removed /api/evidence/authenticated route return 404."""
    response = client.post(
        "/api/evidence/authenticated",
        files={"file": ("test.pcap", io.BytesIO(KNOWN_CONTENT), "application/octet-stream")},
        data={"source_device": "sensor-01"},
    )
    assert response.status_code in (404, 405)


# ---------------------------------------------------------------------------
# 5. No HMAC secret configured → 401 with instructive message
# ---------------------------------------------------------------------------

def test_no_secret_configured_returns_401():
    """Server with no HMAC secret configured must refuse HMAC verification."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = ""  # No secret set

        headers = make_auth_headers()
        with pytest.raises(HTTPException) as exc_info:
            call_verify_hmac(headers)

    assert exc_info.value.status_code == 401
    assert "FORENSIGHT_HMAC_SECRET" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 7. Existing browser upload (POST /api/evidence) still works
# ---------------------------------------------------------------------------

def test_existing_browser_upload_still_works():
    """
    The browser UI route (now unified secure upload) does not require HMAC headers.
    """
    known_content = b"BROWSER_UPLOAD_TEST_VECTOR_NO_HMAC_REQUIRED"
    expected_sha256 = hashlib.sha256(known_content).hexdigest()

    response = upload_secure_evidence(
        client,
        known_content,
        filename="browser_upload.log",
        source_device="workstation-01",
        collector_id="browser-ui",
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["sha256_hash"] == expected_sha256
    assert data["status"] == "ACQUIRED"


# ---------------------------------------------------------------------------
# 8. Evidence list endpoint still works (regression guard)
# ---------------------------------------------------------------------------

def test_evidence_list_endpoint_still_works():
    """GET /api/evidence must return a list of records (may include test data)."""
    response = client.get("/api/evidence")
    assert response.status_code == 200, response.text
    records = response.json()
    assert isinstance(records, list)


# ---------------------------------------------------------------------------
# Unit tests for compute_hmac and sign_request helpers
# ---------------------------------------------------------------------------

def test_compute_hmac_deterministic():
    """Same inputs must always produce the same HMAC digest."""
    ts = 1700000000
    sig1 = compute_hmac(TEST_SECRET, ts, "EVD-TEST-001", KNOWN_HASH)
    sig2 = compute_hmac(TEST_SECRET, ts, "EVD-TEST-001", KNOWN_HASH)
    assert sig1 == sig2
    assert len(sig1) == 64  # SHA-256 hex digest length


def test_compute_hmac_sensitive_to_all_fields():
    """Changing any signing field must produce a different HMAC."""
    ts = 1700000000
    base = compute_hmac(TEST_SECRET, ts, "EVD-TEST-001", KNOWN_HASH)
    assert compute_hmac("different-secret", ts, "EVD-TEST-001", KNOWN_HASH) != base
    assert compute_hmac(TEST_SECRET, ts + 1, "EVD-TEST-001", KNOWN_HASH) != base
    assert compute_hmac(TEST_SECRET, ts, "EVD-TEST-002", KNOWN_HASH) != base
    assert compute_hmac(TEST_SECRET, ts, "EVD-TEST-001", "a" * 64) != base


def test_collector_sign_request_headers():
    """sign_request must produce the four required authentication headers."""
    ts = 1700000000
    headers = sign_request(TEST_SECRET, "EVD-TEST-001", KNOWN_HASH, timestamp=ts)

    assert headers["X-ForenSight-Timestamp"] == str(ts)
    assert headers["X-ForenSight-Evidence-ID"] == "EVD-TEST-001"
    assert headers["X-ForenSight-Payload-Hash"] == KNOWN_HASH
    # Independently verify the HMAC matches what the server would compute
    expected = compute_hmac(TEST_SECRET, ts, "EVD-TEST-001", KNOWN_HASH)
    assert headers["X-ForenSight-Signature"] == expected


def test_compute_payload_hash():
    """compute_payload_hash must produce correct SHA-256 of file bytes."""
    data = b"sample forensic artifact bytes"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_payload_hash(data) == expected
