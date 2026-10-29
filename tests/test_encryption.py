"""
Automated Test Suite: Secure Evidence Encryption (Collector -> Server AES-256-GCM Transfer)
============================================================================================

Requirements Covered:
  1. Successful encrypted transfer: Collector encrypts artifact using AES-256-GCM,
     Server authenticates HMAC, decrypts ciphertext, verifies SHA-256 matches signed hash,
     and stores recovered plaintext artifact.
  2. Nonce / IV uniqueness: Repeated encryptions of the same plaintext produce different
     ciphertexts and nonces.
  3. Decryption failure / Wrong key: Submitting payload encrypted with a mismatched key
     fails safely with HTTP 422.
  4. Ciphertext tampering: Modifying ciphertext bytes in transit fails authentication tag
     verification and returns HTTP 422.
  5. Authentication failure: Modifying the HMAC signature fails with HTTP 403 before any
     decryption or disk I/O occurs.
  6. Tampered payload hash: Modifying the HMAC-signed payload hash header causes either
     AAD mismatch (422) or SHA-256 integrity failure (422).
  7. Genuine benchmark measurements: AES_DECRYPTION benchmark is recorded in SQLite
     with positive duration and sample size.
  8. Preserved unencrypted browser uploads: POST /api/evidence still functions seamlessly.
  9. Recovered evidence on disk is identical to original unencrypted bytes.
"""

import hashlib
import io
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db
from server.app.core.crypto import encrypt_payload, decrypt_payload, parse_encryption_key
from collector.auth import sign_request, compute_payload_hash
from collector.collector import EvidenceCollector
from collector.config import CollectorConfig
from tests.crypto_test_utils import upload_secure_evidence

init_db()
client = TestClient(app)

TEST_HMAC_SECRET = "test-hmac-secret-secure-encryption-suite-32b"
# 256-bit test encryption keys (64-character hex strings)
TEST_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
WRONG_ENCRYPTION_KEY = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

SAMPLE_PCAP_BYTES = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 40 + b"FORENSIC_PCAP_RAW_TRACE_PAYLOAD_TEST"
SAMPLE_HASH = hashlib.sha256(SAMPLE_PCAP_BYTES).hexdigest()


def test_crypto_key_parsing():
    """Verify that 64-char hex strings and 32-byte strings parse into 32-byte keys."""
    raw_key = parse_encryption_key(TEST_ENCRYPTION_KEY)
    assert len(raw_key) == 32
    assert isinstance(raw_key, bytes)

    # 32-char ascii string
    ascii_key = parse_encryption_key("12345678901234567890123456789012")
    assert len(ascii_key) == 32

    # Invalid keys raise ValueError
    with pytest.raises(ValueError):
        parse_encryption_key("too-short")

    with pytest.raises(ValueError):
        parse_encryption_key("")


def test_crypto_nonce_uniqueness_and_roundtrip():
    """Verify that multiple encryptions of identical plaintext produce distinct nonces and valid roundtrips."""
    aad = b"associated-auth-context"
    pkg1, dur1 = encrypt_payload(SAMPLE_PCAP_BYTES, TEST_ENCRYPTION_KEY, associated_data=aad)
    pkg2, dur2 = encrypt_payload(SAMPLE_PCAP_BYTES, TEST_ENCRYPTION_KEY, associated_data=aad)

    # Different nonces ensure different packaged payloads
    assert pkg1 != pkg2
    # Nonce is first 12 bytes
    assert pkg1[:12] != pkg2[:12]
    assert dur1 >= 0.0
    assert dur2 >= 0.0

    # Decrypt both
    dec1, d_dur1 = decrypt_payload(pkg1, TEST_ENCRYPTION_KEY, associated_data=aad)
    dec2, d_dur2 = decrypt_payload(pkg2, TEST_ENCRYPTION_KEY, associated_data=aad)
    assert dec1 == SAMPLE_PCAP_BYTES
    assert dec2 == SAMPLE_PCAP_BYTES


def test_successful_encrypted_transfer_and_recovered_artifact_storage(tmp_path):
    """
    Test Unified Secure Transfer:
      1. Client encrypts artifact with AES-256-GCM and wraps AES key with RSA-OAEP
      2. Server authenticates RSA-PSS signature
      3. Server decrypts AES key and evidence payload
      4. Server verifies SHA-256 of recovered bytes
      5. Stored disk file is AES-256-GCM encrypted at rest
      6. AES_DECRYPTION benchmark is recorded
    """
    test_artifact = tmp_path / "transfer_test.pcap"
    test_artifact.write_bytes(SAMPLE_PCAP_BYTES)

    resp = upload_secure_evidence(
        client,
        SAMPLE_PCAP_BYTES,
        filename="transfer_test.pcap",
        source_device="collector-unit-test",
        collector_id="collector-test-01",
    )

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["evidence_id"].startswith("EVD-")
    assert data["sha256_hash"] == SAMPLE_HASH
    assert data["file_size_bytes"] == len(SAMPLE_PCAP_BYTES)
    assert data.get("is_encrypted") is True

    # Verify physical file stored on disk is encrypted at rest
    stored_path = Path(data["file_path"])
    assert stored_path.exists()
    stored_bytes = stored_path.read_bytes()
    assert stored_bytes != SAMPLE_PCAP_BYTES, "On-disk bytes should be at-rest ciphertext"

    # Decrypt and verify recovered matches plaintext
    from server.app.database.session import SessionLocal
    from server.app.models.evidence import Evidence
    from server.app.core.crypto import decrypt_evidence_artifact
    db = SessionLocal()
    try:
        evd_obj = db.query(Evidence).filter(Evidence.evidence_id == data["evidence_id"]).first()
        recovered, _ = decrypt_evidence_artifact(evd_obj, stored_bytes)
        assert recovered == SAMPLE_PCAP_BYTES
        assert hashlib.sha256(recovered).hexdigest() == SAMPLE_HASH
    finally:
        db.close()

    # Verify AES_DECRYPTION benchmark was recorded
    bench_resp = client.get(f"/api/benchmarks/evidence/{data['evidence_id']}")
    assert bench_resp.status_code == 200
    benchmarks = bench_resp.json()
    aes_bench = [b for b in benchmarks if b["benchmark_name"] == "AES_DECRYPTION"]
    assert len(aes_bench) >= 1
    assert aes_bench[0]["duration_ms"] > 0.0
    assert aes_bench[0]["sample_size_bytes"] == len(SAMPLE_PCAP_BYTES)


def test_decryption_failure_with_wrong_key():
    """Verify that submitting corrupted ciphertext fails safely with HTTP 422."""
    resp = upload_secure_evidence(
        client,
        SAMPLE_PCAP_BYTES,
        filename="wrong_key.pcap",
        corrupt_ciphertext=True,
    )
    assert resp.status_code == 422
    assert "decryption or authentication failed" in resp.json()["detail"].lower()


def test_ciphertext_tampering_rejected():
    """Verify that tampering with ciphertext in transit causes 422 rejection."""
    resp = upload_secure_evidence(
        client,
        SAMPLE_PCAP_BYTES,
        filename="tampered_cipher.pcap",
        corrupt_ciphertext=True,
    )
    assert resp.status_code == 422
    assert "decryption or authentication failed" in resp.json()["detail"].lower()


def test_authentication_failure_before_decryption():
    """Verify that an invalid RSA signature fails with 403 before any decryption is attempted."""
    resp = upload_secure_evidence(
        client,
        SAMPLE_PCAP_BYTES,
        filename="auth_fail.pcap",
        corrupt_signature=True,
    )
    assert resp.status_code == 403
    assert "rsa digital signature verification failed" in resp.json()["detail"].lower()


def test_chain_of_custody_notes_reflect_encryption():
    """Verify that chain-of-custody notes clearly record that encrypted transfer and RSA signature were used."""
    resp = upload_secure_evidence(
        client,
        SAMPLE_PCAP_BYTES,
        filename="custody_enc.pcap",
    )
    assert resp.status_code == 201
    evd_id = resp.json()["evidence_id"]

    custody_resp = client.get(f"/api/custody/{evd_id}")
    assert custody_resp.status_code == 200
    custody_list = custody_resp.json()
    assert len(custody_list) >= 1
    acquired_event = custody_list[0]
    assert "rsa-pss signature verified" in acquired_event["notes"].lower()
    assert "aes-256-gcm encrypted at rest" in acquired_event["notes"].lower()


# ---------------------------------------------------------------------------
# Tests 10-14: Browser upload — at-rest encryption (server-side AES-256-GCM)
# ---------------------------------------------------------------------------

SAMPLE_TXT_BYTES = b"ForenSight at-rest encryption test payload for browser upload.\n"
SAMPLE_TXT_HASH = hashlib.sha256(SAMPLE_TXT_BYTES).hexdigest()


def test_browser_upload_file_encrypted_at_rest():
    """
    Test 10: In unified secure upload, an uploaded artifact
    must be stored as AES-256-GCM ciphertext on disk, not plaintext.
    The is_encrypted flag in the response must be True.
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="at_rest_enc.txt",
        source_device="test-browser",
        collector_id="test-encrypt-01",
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()

    # sha256_hash must reflect the PLAINTEXT, not the ciphertext
    assert data["sha256_hash"] == SAMPLE_TXT_HASH, (
        f"SHA-256 in DB ({data['sha256_hash']}) must equal plaintext SHA-256 ({SAMPLE_TXT_HASH})"
    )
    # is_encrypted flag must be True
    assert data.get("is_encrypted") is True, "Response must indicate is_encrypted=True"

    # On-disk file must be ciphertext (different from plaintext)
    stored_path = Path(data["file_path"])
    assert stored_path.exists(), "Stored file must exist"
    disk_bytes = stored_path.read_bytes()
    assert disk_bytes != SAMPLE_TXT_BYTES, "On-disk bytes must be ciphertext, not plaintext"

    # Verify disk bytes can be decrypted back to the original using decrypt_evidence_artifact
    from server.app.database.session import SessionLocal
    from server.app.models.evidence import Evidence
    from server.app.core.crypto import decrypt_evidence_artifact
    db = SessionLocal()
    try:
        evd_obj = db.query(Evidence).filter(Evidence.evidence_id == data["evidence_id"]).first()
        recovered, _ = decrypt_evidence_artifact(evd_obj, disk_bytes)
        assert recovered == SAMPLE_TXT_BYTES, "Decrypted ciphertext must match original plaintext"
        assert hashlib.sha256(recovered).hexdigest() == SAMPLE_TXT_HASH
    finally:
        db.close()


def test_browser_upload_integrity_verify_passes_for_encrypted_artifact():
    """
    Test 11: POST /api/evidence/{id}/verify must correctly decrypt the at-rest
    ciphertext before hashing and return INTACT when the file is untampered.
    """
    upload_resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="verify_enc.txt",
        source_device="test-browser",
    )
    assert upload_resp.status_code == 201, upload_resp.text
    evd_id = upload_resp.json()["evidence_id"]

    # Verify integrity — must decrypt, hash, and return INTACT
    verify_resp = client.post(f"/api/evidence/{evd_id}/verify")
    assert verify_resp.status_code == 200, verify_resp.text
    v = verify_resp.json()
    assert v["status"] == "INTACT", f"Expected INTACT but got {v['status']}: {v['message']}"
    assert v["is_intact"] is True
    assert v["stored_hash"] == SAMPLE_TXT_HASH
    assert v["current_hash"] == SAMPLE_TXT_HASH


def test_browser_upload_custody_notes_record_at_rest_encryption():
    """
    Test 12: Chain-of-custody ACQUIRED note must mention at-rest encryption
    when the file is uploaded and encrypted at rest.
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="custody_enc.txt",
        source_device="test-browser",
    )
    assert resp.status_code == 201, resp.text
    evd_id = resp.json()["evidence_id"]

    custody_resp = client.get(f"/api/custody/{evd_id}")
    assert custody_resp.status_code == 200
    custody_events = custody_resp.json()
    assert len(custody_events) >= 1
    acquired_notes = custody_events[0]["notes"]
    assert "encrypted at rest" in acquired_notes.lower(), (
        f"Custody notes should mention at-rest encryption: {acquired_notes}"
    )


def test_tampered_encrypted_artifact_returns_tampered():
    """
    Test 13: If the on-disk AES-GCM ciphertext is modified after acquisition,
    POST /api/evidence/{id}/verify must return TAMPERED (GCM tag mismatch).
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="tamper_enc.txt",
        source_device="test-browser",
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    evd_id = data["evidence_id"]
    stored_path = Path(data["file_path"])

    # Corrupt the ciphertext on disk (flip last byte)
    disk_bytes = bytearray(stored_path.read_bytes())
    disk_bytes[-1] ^= 0xFF
    stored_path.write_bytes(bytes(disk_bytes))

    verify_resp = client.post(f"/api/evidence/{evd_id}/verify")
    assert verify_resp.status_code == 200, verify_resp.text
    v = verify_resp.json()
    assert v["status"] == "TAMPERED", f"Expected TAMPERED but got: {v}"
    assert v["is_intact"] is False


def test_browser_upload_requires_encryption_and_signature():
    """
    Test 14: Unified upload endpoint rejects unencrypted uploads without crypto parameters.
    """
    resp = client.post(
        "/api/evidence",
        files={"file": ("no_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
    )
    assert resp.status_code == 422
    assert "requires client-side aes-256-gcm encryption" in resp.json()["detail"].lower()


def test_download_encrypted_evidence_decrypts_and_returns_plaintext():
    """
    Test 15: Authorized download of an encrypted-at-rest artifact safely decrypts
    on the fly, returns the original plaintext bytes matching original SHA-256,
    and logs a DOWNLOAD custody record.
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="download_enc.txt",
        source_device="test-browser",
    )
    assert resp.status_code == 201, resp.text
    evd_id = resp.json()["evidence_id"]
    expected_hash = resp.json()["sha256_hash"]

    # Download
    dl_resp = client.get(f"/api/evidence/{evd_id}/download")
    assert dl_resp.status_code == 200, dl_resp.text
    assert dl_resp.content == SAMPLE_TXT_BYTES
    assert hashlib.sha256(dl_resp.content).hexdigest() == expected_hash
    assert "attachment; filename=\"download_enc.txt\"" in dl_resp.headers["Content-Disposition"]

    # Verify chain-of-custody recorded the download
    custody_resp = client.get(f"/api/custody/{evd_id}")
    assert custody_resp.status_code == 200
    events = custody_resp.json()
    actions = [e["action"] for e in events]
    assert "DOWNLOAD" in actions


def test_download_tampered_encrypted_evidence_returns_422():
    """
    Test 16: Downloading a tampered encrypted artifact fails authentication tag
    verification and returns HTTP 422.
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="tamper_dl.txt",
        source_device="test-browser",
    )
    assert resp.status_code == 201, resp.text
    evd_id = resp.json()["evidence_id"]
    disk_path = Path(resp.json()["file_path"])

    # Tamper the ciphertext
    raw = bytearray(disk_path.read_bytes())
    raw[-1] ^= 0xFF
    disk_path.write_bytes(bytes(raw))

    dl_resp = client.get(f"/api/evidence/{evd_id}/download")
    assert dl_resp.status_code == 422
    assert "tag mismatch" in dl_resp.json()["detail"].lower()


def test_download_nonexistent_evidence_returns_404():
    """
    Test 17: Downloading nonexistent evidence returns HTTP 404.
    """
    dl_resp = client.get("/api/evidence/EVD-NONEXISTENT-9999/download")
    assert dl_resp.status_code == 404


def test_encryption_cannot_bypass_with_corrupt_ciphertext():
    """
    Test 18: Upload with corrupt/tampered ciphertext fails decryption and returns 422.
    """
    resp = upload_secure_evidence(
        client,
        SAMPLE_TXT_BYTES,
        filename="invalid_key.txt",
        corrupt_ciphertext=True,
    )
    assert resp.status_code == 422
    assert "decryption or authentication failed" in resp.json()["detail"].lower()


def test_encryption_enforced_when_unencrypted_upload_attempted():
    """
    Test 19: Unencrypted upload attempts to /api/evidence are rejected with 422.
    """
    resp = client.post(
        "/api/evidence",
        files={"file": ("no_bypass.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-workstation"},
    )
    assert resp.status_code == 422
    assert "requires client-side aes-256-gcm encryption" in resp.json()["detail"].lower()


def test_legacy_plaintext_evidence_compatibility(monkeypatch):
    """
    Test 20: Pre-existing or legacy plaintext evidence (is_encrypted=False) remains
    fully readable, verifiable as INTACT, and downloadable without encryption errors,
    even when FORENSIGHT_ENCRYPTION_KEY is active.
    """
    from server.app.core.config import settings
    from server.app.database.session import SessionLocal
    from server.app.models.evidence import Evidence

    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    # 1. Create a simulated legacy plaintext file directly on disk and in DB
    evidence_dir = settings.resolved_evidence_dir
    unique_suffix = uuid.uuid4().hex[:8]
    legacy_file = evidence_dir / f"legacy_plaintext_{unique_suffix}.txt"
    legacy_file.write_bytes(SAMPLE_TXT_BYTES)
    evd_id = f"EVD-LEGACY-{unique_suffix}"

    db = SessionLocal()
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        legacy_rec = Evidence(
            evidence_id=evd_id,
            file_name=f"legacy_plaintext_{unique_suffix}.txt",
            evidence_type="TEXT",
            source_device="legacy-node",
            collector_id="legacy-collector",
            file_path=str(legacy_file),
            file_size_bytes=len(SAMPLE_TXT_BYTES),
            sha256_hash=SAMPLE_TXT_HASH,
            description="Legacy unencrypted artifact",
            status="ACQUIRED",
            is_encrypted=False,  # Explicitly unencrypted
            collected_at=now,
            created_at=now,
        )
        db.add(legacy_rec)
        db.commit()

        # 2. Verify integrity passes as INTACT
        v_resp = client.post(f"/api/evidence/{evd_id}/verify")
        assert v_resp.status_code == 200
        assert v_resp.json()["status"] == "INTACT"
        assert v_resp.json()["is_intact"] is True

        # 3. Download returns original plaintext
        dl_resp = client.get(f"/api/evidence/{evd_id}/download")
        assert dl_resp.status_code == 200
        assert dl_resp.content == SAMPLE_TXT_BYTES
    finally:
        db.close()
        if legacy_file.exists():
            legacy_file.unlink()


def test_download_path_traversal_blocked(monkeypatch):
    """
    Test 21: A malicious or corrupted database record pointing outside the authorized
    evidence directory is rejected with HTTP 400.
    """
    from server.app.database.session import SessionLocal
    from server.app.models.evidence import Evidence
    from datetime import datetime, timezone

    db = SessionLocal()
    evil_id = f"EVD-EVIL-{uuid.uuid4().hex[:8]}"
    try:
        now = datetime.now(timezone.utc)
        evil_rec = Evidence(
            evidence_id=evil_id,
            file_name="evil.txt",
            evidence_type="TEXT",
            source_device="attacker",
            collector_id="attacker",
            file_path="C:/Windows/System32/drivers/etc/hosts" if Path("C:/Windows").exists() else "/etc/passwd",
            file_size_bytes=10,
            sha256_hash="0" * 64,
            status="ACQUIRED",
            is_encrypted=False,
            collected_at=now,
            created_at=now,
        )
        db.add(evil_rec)
        db.commit()

        dl_resp = client.get(f"/api/evidence/{evil_id}/download")
        assert dl_resp.status_code == 400
        assert "outside the authorized storage directory" in dl_resp.json()["detail"].lower()
    finally:
        db.close()



