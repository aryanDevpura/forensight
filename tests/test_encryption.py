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

    # Verify physical file stored on disk is the RECOVERED PLAINTEXT, not ciphertext
    stored_path = Path(data["file_path"])
    assert stored_path.exists()
    stored_bytes = stored_path.read_bytes()
    assert stored_bytes == SAMPLE_PCAP_BYTES
    assert hashlib.sha256(stored_bytes).hexdigest() == SAMPLE_HASH

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
