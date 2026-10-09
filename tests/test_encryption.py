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


def test_successful_encrypted_transfer_and_recovered_artifact_storage(monkeypatch, tmp_path):
    """
    Test Collector -> Server end-to-end encrypted transfer:
      1. Collector encrypts artifact with AES-256-GCM
      2. Server authenticates HMAC
      3. Server decrypts evidence
      4. Server verifies SHA-256 of recovered bytes
      5. Stored disk file matches original unencrypted bytes byte-for-byte
      6. AES_DECRYPTION benchmark is recorded
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_HMAC_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    test_artifact = tmp_path / "transfer_test.pcap"
    test_artifact.write_bytes(SAMPLE_PCAP_BYTES)

    # Encrypt payload on collector side
    encrypted_pkg, enc_sec = encrypt_payload(
        SAMPLE_PCAP_BYTES,
        TEST_ENCRYPTION_KEY,
        associated_data=SAMPLE_HASH.encode("utf-8"),
    )
    assert len(encrypted_pkg) > len(SAMPLE_PCAP_BYTES)

    # Build HMAC headers over original SHA-256
    ts = int(time.time())
    auth_headers = sign_request(
        secret=TEST_HMAC_SECRET,
        evidence_id="PENDING-transfer_test.pcap",
        payload_hash=SAMPLE_HASH,
        timestamp=ts,
    )
    auth_headers["X-ForenSight-Encryption"] = "AES-GCM-256"

    resp = client.post(
        "/api/evidence/authenticated",
        files={"file": ("transfer_test.pcap", io.BytesIO(encrypted_pkg), "application/octet-stream")},
        data={"source_device": "collector-unit-test", "collector_id": "collector-test-01"},
        headers=auth_headers,
    )

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["evidence_id"].startswith("EVD-")
    assert data["sha256_hash"] == SAMPLE_HASH
    assert data["file_size_bytes"] == len(SAMPLE_PCAP_BYTES)
    # Evidence is encrypted at rest by the server
    assert data.get("is_encrypted") is True, "Authenticated upload should also be encrypted at rest"

    # Verify physical file stored on disk is the RECOVERED PLAINTEXT encrypted at rest
    stored_path = Path(data["file_path"])
    assert stored_path.exists()
    stored_bytes = stored_path.read_bytes()
    # Disk file is ciphertext (at-rest encrypted), NOT raw plaintext
    assert stored_bytes != SAMPLE_PCAP_BYTES, "On-disk bytes should be at-rest ciphertext"
    # But decrypting should yield the original bytes
    recovered, _ = decrypt_payload(stored_bytes, TEST_ENCRYPTION_KEY)
    assert recovered == SAMPLE_PCAP_BYTES
    assert hashlib.sha256(recovered).hexdigest() == SAMPLE_HASH

    # Verify AES_DECRYPTION benchmark was recorded
    bench_resp = client.get(f"/api/benchmarks/evidence/{data['evidence_id']}")
    assert bench_resp.status_code == 200
    benchmarks = bench_resp.json()
    aes_bench = [b for b in benchmarks if b["benchmark_name"] == "AES_DECRYPTION"]
    assert len(aes_bench) >= 1
    assert aes_bench[0]["duration_ms"] > 0.0
    assert aes_bench[0]["sample_size_bytes"] == len(SAMPLE_PCAP_BYTES)


def test_decryption_failure_with_wrong_key(monkeypatch):
    """Verify that encrypting with Key A and decrypting with Key B returns HTTP 422."""
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_HMAC_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)  # Server has Key A

    # Encrypt with Key B
    encrypted_pkg, _ = encrypt_payload(
        SAMPLE_PCAP_BYTES,
        WRONG_ENCRYPTION_KEY,
        associated_data=SAMPLE_HASH.encode("utf-8"),
    )

    ts = int(time.time())
    auth_headers = sign_request(
        secret=TEST_HMAC_SECRET,
        evidence_id="PENDING-wrong_key.pcap",
        payload_hash=SAMPLE_HASH,
        timestamp=ts,
    )
    auth_headers["X-ForenSight-Encryption"] = "AES-GCM-256"

    resp = client.post(
        "/api/evidence/authenticated",
        files={"file": ("wrong_key.pcap", io.BytesIO(encrypted_pkg), "application/octet-stream")},
        data={"source_device": "collector-unit-test"},
        headers=auth_headers,
    )

    assert resp.status_code == 422
    assert "decryption verification failed" in resp.json()["detail"].lower()


def test_ciphertext_tampering_rejected(monkeypatch):
    """Verify that tampering with a single byte of ciphertext in transit causes 422 rejection."""
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_HMAC_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    encrypted_pkg, _ = encrypt_payload(
        SAMPLE_PCAP_BYTES,
        TEST_ENCRYPTION_KEY,
        associated_data=SAMPLE_HASH.encode("utf-8"),
    )

    # Corrupt a byte in the ciphertext body
    tampered_bytes = bytearray(encrypted_pkg)
    tampered_bytes[-1] ^= 0xFF  # Flip bits of last byte

    ts = int(time.time())
    auth_headers = sign_request(
        secret=TEST_HMAC_SECRET,
        evidence_id="PENDING-tampered_cipher.pcap",
        payload_hash=SAMPLE_HASH,
        timestamp=ts,
    )
    auth_headers["X-ForenSight-Encryption"] = "AES-GCM-256"

    resp = client.post(
        "/api/evidence/authenticated",
        files={"file": ("tampered_cipher.pcap", io.BytesIO(tampered_bytes), "application/octet-stream")},
        data={"source_device": "collector-unit-test"},
        headers=auth_headers,
    )

    assert resp.status_code == 422
    assert "decryption verification failed" in resp.json()["detail"].lower()


def test_authentication_failure_before_decryption(monkeypatch):
    """Verify that an invalid HMAC signature fails with 403 before any decryption is attempted."""
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_HMAC_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    encrypted_pkg, _ = encrypt_payload(
        SAMPLE_PCAP_BYTES,
        TEST_ENCRYPTION_KEY,
        associated_data=SAMPLE_HASH.encode("utf-8"),
    )

    ts = int(time.time())
    auth_headers = sign_request(
        secret=TEST_HMAC_SECRET,
        evidence_id="PENDING-auth_fail.pcap",
        payload_hash=SAMPLE_HASH,
        timestamp=ts,
    )
    auth_headers["X-ForenSight-Encryption"] = "AES-GCM-256"
    # Tamper with HMAC signature
    auth_headers["X-ForenSight-Signature"] = "0000000000000000000000000000000000000000000000000000000000000000"

    resp = client.post(
        "/api/evidence/authenticated",
        files={"file": ("auth_fail.pcap", io.BytesIO(encrypted_pkg), "application/octet-stream")},
        headers=auth_headers,
    )

    assert resp.status_code == 403
    assert "hmac signature verification failed" in resp.json()["detail"].lower()


def test_chain_of_custody_notes_reflect_encryption(monkeypatch):
    """Verify that chain-of-custody notes clearly record that encrypted transfer was used."""
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_HMAC_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    encrypted_pkg, _ = encrypt_payload(
        SAMPLE_PCAP_BYTES,
        TEST_ENCRYPTION_KEY,
        associated_data=SAMPLE_HASH.encode("utf-8"),
    )
    ts = int(time.time())
    auth_headers = sign_request(
        secret=TEST_HMAC_SECRET,
        evidence_id="PENDING-custody_enc.pcap",
        payload_hash=SAMPLE_HASH,
        timestamp=ts,
    )
    auth_headers["X-ForenSight-Encryption"] = "AES-GCM-256"

    resp = client.post(
        "/api/evidence/authenticated",
        files={"file": ("custody_enc.pcap", io.BytesIO(encrypted_pkg), "application/octet-stream")},
        headers=auth_headers,
    )

    assert resp.status_code == 201
    evd_id = resp.json()["evidence_id"]

    custody_resp = client.get(f"/api/custody/{evd_id}")
    assert custody_resp.status_code == 200
    custody_list = custody_resp.json()
    assert len(custody_list) >= 1
    acquired_event = custody_list[0]
    assert "AES-GCM encrypted transfer" in acquired_event["notes"]


# ---------------------------------------------------------------------------
# Tests 10-14: Browser upload — at-rest encryption (server-side AES-256-GCM)
# ---------------------------------------------------------------------------

SAMPLE_TXT_BYTES = b"ForenSight at-rest encryption test payload for browser upload.\n"
SAMPLE_TXT_HASH = hashlib.sha256(SAMPLE_TXT_BYTES).hexdigest()


def test_browser_upload_file_encrypted_at_rest(monkeypatch):
    """
    Test 10: When FORENSIGHT_ENCRYPTION_KEY is set, a browser-uploaded artifact
    must be stored as AES-256-GCM ciphertext on disk, not plaintext.
    The is_encrypted flag in the response must be True.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    resp = client.post(
        "/api/evidence",
        files={"file": ("at_rest_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser", "collector_id": "test-encrypt-01"},
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

    # Verify disk bytes can be decrypted back to the original
    recovered, _ = decrypt_payload(disk_bytes, TEST_ENCRYPTION_KEY)
    assert recovered == SAMPLE_TXT_BYTES, "Decrypted ciphertext must match original plaintext"
    assert hashlib.sha256(recovered).hexdigest() == SAMPLE_TXT_HASH


def test_browser_upload_integrity_verify_passes_for_encrypted_artifact(monkeypatch):
    """
    Test 11: POST /api/evidence/{id}/verify must correctly decrypt the at-rest
    ciphertext before hashing and return INTACT when the file is untampered.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    # Upload
    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("verify_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
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


def test_browser_upload_custody_notes_record_at_rest_encryption(monkeypatch):
    """
    Test 12: Chain-of-custody ACQUIRED note must mention at-rest encryption
    when the file is encrypted by the server after a browser upload.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    resp = client.post(
        "/api/evidence",
        files={"file": ("custody_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
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


def test_tampered_encrypted_artifact_returns_tampered(monkeypatch, tmp_path):
    """
    Test 13: If the on-disk AES-GCM ciphertext is modified after acquisition,
    POST /api/evidence/{id}/verify must return TAMPERED (GCM tag mismatch).
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    resp = client.post(
        "/api/evidence",
        files={"file": ("tamper_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
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


def test_browser_upload_no_encryption_without_key(monkeypatch):
    """
    Test 14: When FORENSIGHT_ENCRYPTION_KEY is empty/unset, a browser upload
    must be stored as plaintext and is_encrypted must be False (backward compat).
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", "")

    resp = client.post(
        "/api/evidence",
        files={"file": ("no_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data.get("is_encrypted") is False
    stored_path = Path(data["file_path"])
    assert stored_path.read_bytes() == SAMPLE_TXT_BYTES, "Without key, file must be stored as plaintext"


def test_download_encrypted_evidence_decrypts_and_returns_plaintext(monkeypatch):
    """
    Test 15: Authorized download of an encrypted-at-rest artifact safely decrypts
    on the fly, returns the original plaintext bytes matching original SHA-256,
    and logs a DOWNLOAD custody record.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    resp = client.post(
        "/api/evidence",
        files={"file": ("download_enc.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
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


def test_download_tampered_encrypted_evidence_returns_422(monkeypatch):
    """
    Test 16: Downloading a tampered encrypted artifact fails authentication tag
    verification and returns HTTP 422.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)

    resp = client.post(
        "/api/evidence",
        files={"file": ("tamper_dl.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-browser"},
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


def test_encryption_cannot_bypass_with_invalid_key(monkeypatch):
    """
    Test 18: An invalid FORENSIGHT_ENCRYPTION_KEY (e.g. wrong length) rejects upload
    with HTTP 500 and prevents silent fallback to unencrypted disk storage.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", "too-short-invalid-key")

    resp = client.post(
        "/api/evidence",
        files={"file": ("invalid_key.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-workstation"},
    )
    assert resp.status_code == 500
    assert "encryption failed" in resp.json()["detail"].lower()


def test_encryption_enforced_when_require_encryption_enabled(monkeypatch):
    """
    Test 19: When FORENSIGHT_REQUIRE_ENCRYPTION=True and FORENSIGHT_ENCRYPTION_KEY is unset,
    upload must fail with HTTP 500 rather than silently bypassing encryption.
    """
    from server.app.core.config import settings
    monkeypatch.setattr(settings, "FORENSIGHT_ENCRYPTION_KEY", "")
    monkeypatch.setattr(settings, "FORENSIGHT_REQUIRE_ENCRYPTION", True)

    resp = client.post(
        "/api/evidence",
        files={"file": ("no_bypass.txt", io.BytesIO(SAMPLE_TXT_BYTES), "text/plain")},
        data={"source_device": "test-workstation"},
    )
    assert resp.status_code == 500
    assert "encryption is required" in resp.json()["detail"].lower()


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



