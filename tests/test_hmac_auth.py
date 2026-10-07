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

from server.app.main import app
from server.app.database.session import init_db
from server.app.core.hmac_auth import compute_hmac, REPLAY_WINDOW_SECONDS
from collector.auth import compute_payload_hash, sign_request

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


def post_authenticated(
    content: bytes = KNOWN_CONTENT,
    filename: str = "test_artifact.pcap",
    headers: dict | None = None,
    extra_data: dict | None = None,
):
    """Helper: POST to /api/evidence/authenticated."""
    if headers is None:
        headers = make_auth_headers()
    data = extra_data or {}
    return client.post(
        "/api/evidence/authenticated",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
        data={"source_device": "sensor-alpha-01", "collector_id": "test-collector", **data},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# 1. Valid authenticated request succeeds
# ---------------------------------------------------------------------------

def test_valid_authenticated_upload_succeeds():
    """A correctly signed request must be accepted and return 201."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        response = post_authenticated()

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["evidence_id"].startswith("EVD-")
    assert data["evidence_type"] == "PCAP"
    assert data["sha256_hash"] == KNOWN_HASH
    assert data["status"] == "ACQUIRED"


# ---------------------------------------------------------------------------
# 2. Tampered signature is rejected (403)
# ---------------------------------------------------------------------------

def test_tampered_signature_is_rejected():
    """A request with a forged/corrupted HMAC signature must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        headers = make_auth_headers()
        # Flip a character in the signature to simulate tampering
        good_sig = headers["X-ForenSight-Signature"]
        tampered_char = "0" if good_sig[0] != "0" else "1"
        headers["X-ForenSight-Signature"] = tampered_char + good_sig[1:]

        response = post_authenticated(headers=headers)

    assert response.status_code == 403, response.text
    assert "HMAC signature verification failed" in response.json()["detail"]


def test_wrong_secret_is_rejected():
    """A request signed with a different secret must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        # Sign with a different secret
        headers = sign_request(
            secret="completely-wrong-secret",
            evidence_id=TEST_EVIDENCE_ID,
            payload_hash=KNOWN_HASH,
        )
        response = post_authenticated(headers=headers)

    assert response.status_code == 403, response.text
    assert "HMAC signature verification failed" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Expired / replayed timestamp is rejected (401)
# ---------------------------------------------------------------------------

def test_expired_timestamp_is_rejected():
    """A request with a timestamp older than the replay window must be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        expired_ts = int(time.time()) - (REPLAY_WINDOW_SECONDS + 60)
        headers = make_auth_headers(timestamp=expired_ts)
        response = post_authenticated(headers=headers)

    assert response.status_code == 401, response.text
    detail = response.json()["detail"]
    assert "replay window" in detail.lower()


def test_future_timestamp_beyond_window_is_rejected():
    """A request with a timestamp far in the future must also be rejected."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        future_ts = int(time.time()) + (REPLAY_WINDOW_SECONDS + 60)
        headers = make_auth_headers(timestamp=future_ts)
        response = post_authenticated(headers=headers)

    assert response.status_code == 401, response.text
    assert "replay window" in response.json()["detail"].lower()


def test_timestamp_within_window_is_accepted():
    """A request timestamp at the edge of the allowed window must succeed."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        # 10 seconds before the window boundary (well within the window)
        near_edge_ts = int(time.time()) - (REPLAY_WINDOW_SECONDS - 10)
        headers = make_auth_headers(timestamp=near_edge_ts)
        response = post_authenticated(headers=headers)

    assert response.status_code == 201, response.text


# ---------------------------------------------------------------------------
# 4. Missing HMAC headers → 422 (FastAPI header validation)
# ---------------------------------------------------------------------------

def test_missing_auth_headers_rejected():
    """Requests with no HMAC headers at all must be rejected at validation."""
    response = client.post(
        "/api/evidence/authenticated",
        files={"file": ("test.pcap", io.BytesIO(KNOWN_CONTENT), "application/octet-stream")},
        data={"source_device": "sensor-01"},
        # No HMAC headers
    )
    # FastAPI returns 422 when required headers are absent
    assert response.status_code == 422, response.text


# ---------------------------------------------------------------------------
# 5. Payload hash mismatch (in-transit tampering) → 422
# ---------------------------------------------------------------------------

def test_payload_mismatch_is_rejected():
    """
    If the file bytes received differ from the hash in the signed headers,
    the server must detect in-transit tampering and reject the upload.
    """
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = TEST_SECRET

        original_content = b"ORIGINAL_PAYLOAD"
        original_hash = hashlib.sha256(original_content).hexdigest()
        # Sign over the original hash, but send different (tampered) bytes
        tampered_content = b"TAMPERED_PAYLOAD_DIFFERENT"
        headers = sign_request(
            secret=TEST_SECRET,
            evidence_id=TEST_EVIDENCE_ID,
            payload_hash=original_hash,  # signed hash of ORIGINAL
        )
        response = client.post(
            "/api/evidence/authenticated",
            files={"file": ("tampered.pcap", io.BytesIO(tampered_content), "application/octet-stream")},
            data={"source_device": "sensor-01"},
            headers=headers,
        )

    assert response.status_code == 422, response.text
    assert "integrity check failed" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. No HMAC secret configured → 401 with instructive message
# ---------------------------------------------------------------------------

def test_no_secret_configured_returns_401():
    """Server with no HMAC secret configured must refuse all collector uploads."""
    with patch("server.app.core.hmac_auth.settings") as mock_settings:
        mock_settings.FORENSIGHT_HMAC_SECRET = ""  # No secret set

        headers = make_auth_headers()
        response = post_authenticated(headers=headers)

    assert response.status_code == 401, response.text
    assert "FORENSIGHT_HMAC_SECRET" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 7. Existing browser upload (POST /api/evidence) still works
# ---------------------------------------------------------------------------

def test_existing_browser_upload_still_works():
    """
    The unauthenticated browser UI route must continue to accept uploads
    without any HMAC headers (no regression).
    """
    known_content = b"BROWSER_UPLOAD_TEST_VECTOR_NO_HMAC_REQUIRED"
    expected_sha256 = hashlib.sha256(known_content).hexdigest()

    response = client.post(
        "/api/evidence",
        files={"file": ("browser_upload.log", io.BytesIO(known_content), "text/plain")},
        data={"source_device": "workstation-01", "collector_id": "browser-ui"},
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
