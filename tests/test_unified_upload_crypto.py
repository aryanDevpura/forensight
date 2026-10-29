"""
Comprehensive Test Suite: ForenSight Unified Secure Evidence Upload & Cryptography
==================================================================================
Covers requirements 1-21 of Section 13:
  1. Successful TXT upload.
  2. Successful binary/image upload.
  3. Successful PCAP upload.
  4. Correct SHA-256 calculation and verification.
  5. Successful RSA-PSS signature verification.
  6. Invalid or modified signature rejection.
  7. Untrusted public-key rejection.
  8. Modified ciphertext rejection.
  9. Invalid AES-GCM authentication-tag rejection.
  10. Digest mismatch rejection.
  11. Missing or invalid key configuration handling.
  12. Authorized download returns byte-for-byte identical original data.
  13. Tampered stored ciphertext is rejected on download.
  14. Download integrity verification failure does not return corrupted data.
  15. Correct acquisition/custody event creation for successful uploads.
  16. No successful acquisition event for failed uploads.
  17. Existing custody-history retrieval still works.
  18. Existing PCAP analysis and findings still work.
  19. Existing timeline and report functionality still works.
  20. Existing benchmark endpoints still work.
  21. Existing evidence records remain accessible after migration.
"""

import io
import time
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from Crypto.PublicKey import RSA

from server.app.main import app
from server.app.database.session import init_db, SessionLocal
from server.app.models.evidence import Evidence
from server.app.models.custody import ChainOfCustody
from server.app.core.rsa_crypto import (
    init_rsa_keys,
    get_server_public_key,
    get_client_demo_private_key,
    DEFAULT_SIGNER_ID,
)
from tests.crypto_test_utils import (
    create_signed_encrypted_payload,
    upload_secure_evidence,
)

init_db()
init_rsa_keys()
client = TestClient(app)

SAMPLE_TXT = b"INCIDENT_REPORT_TEXT_LOG_ARTEFACT_LINE_1\nINCIDENT_REPORT_LINE_2\n"
SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
SAMPLE_PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32 + b"FORENSIC_PCAP_PACKET_TRACE_UNIFIED_TEST_VECTOR_2026"


# ---------------------------------------------------------------------------
# 1. Successful TXT Upload
# ---------------------------------------------------------------------------
def test_successful_txt_upload():
    resp = upload_secure_evidence(
        client=client,
        content=SAMPLE_TXT,
        filename="incident_notes.txt",
        source_device="investigator-laptop",
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["file_name"] == "incident_notes.txt"
    assert data["evidence_type"] == "TEXT"
    assert data["sha256_hash"] == hashlib.sha256(SAMPLE_TXT).hexdigest()
    assert data["is_encrypted"] is True
    assert data["status"] == "ACQUIRED"


# ---------------------------------------------------------------------------
# 2. Successful Binary / Image Upload
# ---------------------------------------------------------------------------
def test_successful_image_upload():
    resp = upload_secure_evidence(
        client=client,
        content=SAMPLE_PNG,
        filename="disk_snapshot.png",
        source_device="imaging-station",
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["file_name"] == "disk_snapshot.png"
    assert data["evidence_type"] == "IMAGE"
    assert data["file_size_bytes"] == len(SAMPLE_PNG)
    assert data["sha256_hash"] == hashlib.sha256(SAMPLE_PNG).hexdigest()
    assert data["is_encrypted"] is True


# ---------------------------------------------------------------------------
# 3. Successful PCAP Upload
# ---------------------------------------------------------------------------
def test_successful_pcap_upload():
    resp = upload_secure_evidence(
        client=client,
        content=SAMPLE_PCAP,
        filename="network_capture.pcap",
        source_device="gateway-mirror",
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["file_name"] == "network_capture.pcap"
    assert data["evidence_type"] == "PCAP"
    assert data["sha256_hash"] == hashlib.sha256(SAMPLE_PCAP).hexdigest()


# ---------------------------------------------------------------------------
# 4. Correct SHA-256 Calculation and Verification
# ---------------------------------------------------------------------------
def test_sha256_integrity_match():
    content = b"CUSTOM_FORENSIGHT_VERIFICATION_BYTES_SHA256"
    expected = hashlib.sha256(content).hexdigest()
    resp = upload_secure_evidence(
        client=client,
        content=content,
        filename="verify_sha.log",
    )
    assert resp.status_code == 201
    assert resp.json()["sha256_hash"] == expected


# ---------------------------------------------------------------------------
# 5. Successful RSA-PSS Signature Verification
# ---------------------------------------------------------------------------
def test_rsa_pss_signature_verified():
    resp = upload_secure_evidence(
        client=client,
        content=b"RSA_PSS_TEST_BYTES",
        filename="signed_artifact.log",
        signer_key_id=DEFAULT_SIGNER_ID,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["signer_key_id"] == DEFAULT_SIGNER_ID
    assert data["rsa_signature"] is not None


# ---------------------------------------------------------------------------
# 6. Invalid or Modified Signature Rejection (HTTP 403)
# ---------------------------------------------------------------------------
def test_tampered_signature_rejected():
    resp = upload_secure_evidence(
        client=client,
        content=b"CORRUPT_SIG_PAYLOAD",
        filename="corrupt_sig.log",
        corrupt_signature=True,
    )
    assert resp.status_code == 403
    assert "signature verification failed" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 7. Untrusted Public-Key Rejection (HTTP 403)
# ---------------------------------------------------------------------------
def test_untrusted_public_key_rejected():
    # Generate an unknown rogue key pair
    rogue_key = RSA.generate(2048)
    resp = upload_secure_evidence(
        client=client,
        content=b"UNTRUSTED_KEY_CONTENT",
        filename="untrusted_key.log",
        signer_key_id="rogue-signer-99",
        client_private_key=rogue_key,
    )
    assert resp.status_code == 403
    assert "untrusted" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 8. Modified Ciphertext Rejection (HTTP 422)
# ---------------------------------------------------------------------------
def test_modified_ciphertext_rejected():
    resp = upload_secure_evidence(
        client=client,
        content=b"TAMPERED_CIPHERTEXT_TEST_1234567890",
        filename="tampered_cipher.pcap",
        corrupt_ciphertext=True,
    )
    # Tampering ciphertext causes either signature mismatch or GCM tag failure (403/422)
    assert resp.status_code in (403, 422)


# ---------------------------------------------------------------------------
# 9. Invalid AES-GCM Authentication-Tag Rejection (HTTP 422)
# ---------------------------------------------------------------------------
def test_invalid_tag_rejected():
    resp = upload_secure_evidence(
        client=client,
        content=b"TAMPERED_TAG_TEST_1234567890",
        filename="tampered_tag.pcap",
        corrupt_tag=True,
    )
    assert resp.status_code in (403, 422)


# ---------------------------------------------------------------------------
# 10. Digest Mismatch Rejection (HTTP 422)
# ---------------------------------------------------------------------------
def test_digest_mismatch_rejected():
    resp = upload_secure_evidence(
        client=client,
        content=b"DIGEST_MISMATCH_DATA",
        filename="mismatch.log",
        corrupt_digest=True,
    )
    # The signature will cover the corrupt digest, so signature verifies, but plaintext SHA-256 fails!
    assert resp.status_code == 422
    assert "integrity verification failed" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 11. Missing Key Configuration Handling
# ---------------------------------------------------------------------------
def test_missing_crypto_parameters_rejected():
    # Direct upload without cryptographic parameters
    resp = client.post(
        "/api/evidence",
        files={"file": ("raw.txt", io.BytesIO(b"NO_CRYPTO"), "text/plain")},
        data={"source_device": "raw-device"},
    )
    assert resp.status_code == 422
    assert "missing required parameters" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 12. Authorized Download Returns Byte-for-Byte Identical Original Data
# ---------------------------------------------------------------------------
def test_authorized_download_exact_match():
    payload = b"EXACT_BYTE_MATCH_DOWNLOAD_TEST_PAYLOAD_" + b"\x00\xff\xfe\x01\x80" * 20
    resp = upload_secure_evidence(
        client=client,
        content=payload,
        filename="exact_match.log",
    )
    assert resp.status_code == 201
    ev_id = resp.json()["evidence_id"]

    # Download
    dl_resp = client.get(f"/api/evidence/{ev_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.content == payload
    assert dl_resp.headers.get("X-ForenSight-SHA256") == hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# 13. Tampered Stored Ciphertext is Rejected on Download
# ---------------------------------------------------------------------------
def test_tampered_stored_ciphertext_rejected_on_download():
    payload = b"TAMPER_ON_DISK_BEFORE_DOWNLOAD_TEST"
    resp = upload_secure_evidence(
        client=client,
        content=payload,
        filename="tamper_disk.log",
    )
    assert resp.status_code == 201
    data = resp.json()
    ev_id = data["evidence_id"]
    disk_path = Path(data["file_path"])

    # Tamper with file on disk directly
    raw_disk = bytearray(disk_path.read_bytes())
    raw_disk[-5] ^= 0xFF
    disk_path.write_bytes(bytes(raw_disk))

    # Attempt download -> must be rejected with HTTP 422
    dl_resp = client.get(f"/api/evidence/{ev_id}/download")
    assert dl_resp.status_code == 422
    assert "decryption failed" in dl_resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 14. Download Integrity Verification Failure Does Not Return Corrupted Data
# ---------------------------------------------------------------------------
def test_download_failure_no_corrupted_data():
    payload = b"CORRUPTED_STORAGE_REJECTION_DATA"
    resp = upload_secure_evidence(
        client=client,
        content=payload,
        filename="tamper_tag_disk.log",
    )
    data = resp.json()
    ev_id = data["evidence_id"]
    disk_path = Path(data["file_path"])

    # Corrupt the 16-byte GCM tag on disk
    raw_disk = bytearray(disk_path.read_bytes())
    raw_disk[15] ^= 0xAA
    disk_path.write_bytes(bytes(raw_disk))

    dl_resp = client.get(f"/api/evidence/{ev_id}/download")
    assert dl_resp.status_code == 422
    # Verify no partial or corrupt payload was returned
    assert dl_resp.content != payload


# ---------------------------------------------------------------------------
# 15. Correct Acquisition Custody Event Creation for Successful Uploads
# ---------------------------------------------------------------------------
def test_custody_event_created_on_successful_upload():
    resp = upload_secure_evidence(
        client=client,
        content=b"CUSTODY_TEST_DATA",
        filename="custody_verified.log",
    )
    assert resp.status_code == 201
    ev_id = resp.json()["evidence_id"]

    custody_resp = client.get(f"/api/custody/{ev_id}")
    assert custody_resp.status_code == 200
    events = custody_resp.json()
    assert len(events) >= 1
    acq = events[0]
    assert acq["action"] == "ACQUIRED"
    assert "RSA-PSS" in acq["notes"]
    assert "AES-256-GCM" in acq["notes"]


# ---------------------------------------------------------------------------
# 16. No Successful Acquisition Event for Failed Uploads
# ---------------------------------------------------------------------------
def test_no_custody_event_on_failed_upload():
    db = SessionLocal()
    count_before = db.query(ChainOfCustody).filter(ChainOfCustody.action == "ACQUIRED").count()
    db.close()

    # Attempt invalid upload (corrupt signature)
    resp = upload_secure_evidence(
        client=client,
        content=b"FAILURE_NO_CUSTODY_EVENT",
        filename="fail.log",
        corrupt_signature=True,
    )
    assert resp.status_code == 403

    db = SessionLocal()
    count_after = db.query(ChainOfCustody).filter(ChainOfCustody.action == "ACQUIRED").count()
    db.close()
    assert count_after == count_before


# ---------------------------------------------------------------------------
# 17. Existing Custody-History Retrieval Still Works
# ---------------------------------------------------------------------------
def test_custody_history_retrieval():
    resp = upload_secure_evidence(
        client=client,
        content=b"CUSTODY_RETRIEVAL_TEST",
        filename="custody_hist.log",
    )
    assert resp.status_code == 201
    ev_id = resp.json()["evidence_id"]

    custody_resp = client.get(f"/api/custody/{ev_id}")
    assert custody_resp.status_code == 200
    chain = custody_resp.json()
    assert len(chain) >= 1
    assert chain[0]["action"] == "ACQUIRED"


# ---------------------------------------------------------------------------
# 18. Existing PCAP Analysis & Findings Still Work
# ---------------------------------------------------------------------------
def test_pcap_analysis_on_newly_uploaded_evidence():
    import struct, socket
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    src_ip = socket.inet_aton("192.168.1.10")
    dst_ip = socket.inet_aton("10.0.0.1")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src_ip, dst_ip)
    tcp = struct.pack("!HHIIHHHH", 54321, 80, 100, 0, (5 << 12) | 0x02, 65535, 0, 0)
    pkt = eth + ip + tcp
    ph = struct.pack("<IIII", 1710000000, 0, len(pkt), len(pkt))
    pcap_data = bytes(gh + ph + pkt)

    resp = upload_secure_evidence(
        client=client,
        content=pcap_data,
        filename="traffic_analysis.pcap",
    )
    assert resp.status_code == 201
    ev_id = resp.json()["evidence_id"]

    # Run analysis
    analysis_resp = client.post(f"/api/analysis/{ev_id}")
    assert analysis_resp.status_code == 200
    data = analysis_resp.json()
    assert data["evidence_id"] == ev_id
    assert data["is_valid_pcap"] is True


# ---------------------------------------------------------------------------
# 19. Existing Timeline and Report Functionality Still Works
# ---------------------------------------------------------------------------
def test_timeline_retrieval():
    resp = client.get("/api/timeline")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 20. Existing Benchmark Endpoints Still Work
# ---------------------------------------------------------------------------
def test_benchmarks_retrieval():
    resp = client.get("/api/benchmarks")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    summary_resp = client.get("/api/benchmarks/summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert "operations" in summary
    assert "RSA_VERIFICATION" in summary["operations"]


# ---------------------------------------------------------------------------
# 21. Existing Evidence Records Remain Accessible After Migration
# ---------------------------------------------------------------------------
def test_existing_evidence_records_accessible():
    resp = client.get("/api/evidence")
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) > 0
    first = records[0]
    assert "evidence_id" in first
    assert "sha256_hash" in first
    assert "status" in first


# ---------------------------------------------------------------------------
# 22. Obsolete Collector Upload Endpoint Is No Longer Active
# ---------------------------------------------------------------------------
def test_obsolete_collector_endpoint_no_longer_active():
    """The separate /api/evidence/authenticated route is removed and returns 404/405."""
    resp = client.post("/api/evidence/authenticated")
    assert resp.status_code in (404, 405)
