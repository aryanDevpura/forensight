import io
import time
import pytest
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import SessionLocal, init_db
from server.app.models.evidence import Evidence
from tests.test_timeline import build_test_pcap
from tests.crypto_test_utils import (
    create_signed_encrypted_payload,
    upload_secure_evidence,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()


def test_crypto_lab_metadata_nonexistent_returns_404():
    """Requesting crypto lab metadata for a non-existent evidence ID must return 404."""
    resp = client.get("/api/evidence/EVD-NONEXISTENT-9999/crypto-lab")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_crypto_lab_decrypt_nonexistent_returns_404():
    """Executing decryption for a non-existent evidence ID must return 404."""
    resp = client.post("/api/evidence/EVD-NONEXISTENT-9999/crypto-lab/decrypt")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_crypto_lab_text_file_lifecycle_and_preview():
    """
    Test TXT evidence in Crypto Lab:
      1. Upload text artifact with measured encryption duration.
      2. Fetch metadata (no decryption performed).
      3. Execute decryption: verify bounded ciphertext preview, decrypted text preview, and throughput.
    """
    text_content = b"ForenSight Cryptography Lab Test Artifact -- Confidential Forensic Notes 2026.\nLine 2\n"
    filename = "crypto_notes.txt"

    # Upload with explicit encryption_duration_ms
    packaged, form_data = create_signed_encrypted_payload(
        content=text_content,
        filename=filename,
        source_device="lab-workstation-01",
    )
    form_data["encryption_duration_ms"] = 14.52

    upload_resp = client.post(
        "/api/evidence",
        files={"file": (filename, io.BytesIO(packaged), "application/octet-stream")},
        data=form_data,
    )
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # 1. Fetch metadata without decrypting
    meta_resp = client.get(f"/api/evidence/{ev_id}/crypto-lab")
    assert meta_resp.status_code == 200
    meta = meta_resp.json()
    assert meta["evidence_id"] == ev_id
    assert meta["is_encrypted"] is True
    assert meta["encryption_algorithm"] == "AES-256-GCM"
    assert meta["has_wrapped_key"] is True
    assert meta["is_pcap"] is False
    assert meta["recorded_encryption_duration_ms"] is not None
    assert abs(meta["recorded_encryption_duration_ms"] - 14.52) < 0.1

    # 2. Execute explicit decryption demonstration
    dec_resp = client.post(f"/api/evidence/{ev_id}/crypto-lab/decrypt")
    assert dec_resp.status_code == 200
    res = dec_resp.json()

    assert res["evidence_id"] == ev_id
    assert res["is_pcap"] is False
    assert res["gcm_authentication_valid"] is True
    assert res["integrity_status"] == "VERIFIED_INTACT"
    assert res["original_size_bytes"] == len(text_content)
    assert res["encrypted_size_bytes"] == len(packaged)

    # Ciphertext preview checks (bounded)
    assert res["ciphertext_preview_hex"] is not None
    assert res["ciphertext_preview_b64"] is not None
    assert res["ciphertext_preview_bytes"] > 0
    assert res["nonce_hex"] is not None
    assert res["tag_hex"] is not None

    # Plaintext preview checks
    assert res["plaintext_preview_type"] == "text"
    assert "ForenSight Cryptography Lab Test Artifact" in res["plaintext_preview"]

    # Performance timing checks
    assert res["decryption_duration_ms"] >= 0
    assert res["decryption_throughput_mbps"] is not None
    assert res["decryption_throughput_mbps"] > 0


def test_crypto_lab_image_file_preview():
    """
    Test IMAGE evidence in Crypto Lab:
      Decryption must validate image magic bytes and provide a bounded base64 data URI preview.
    """
    # 1x1 transparent PNG file bytes
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15"
        b"\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    filename = "forensic_snapshot.png"

    upload_resp = upload_secure_evidence(client, png_bytes, filename=filename)
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # Execute decryption demonstration
    dec_resp = client.post(f"/api/evidence/{ev_id}/crypto-lab/decrypt")
    assert dec_resp.status_code == 200
    res = dec_resp.json()

    assert res["is_pcap"] is False
    assert res["plaintext_preview_type"] == "image"
    assert res["plaintext_preview"].startswith("data:image/png;base64,")
    assert res["ciphertext_preview_hex"] is not None
    assert res["gcm_authentication_valid"] is True
    assert res["integrity_status"] == "VERIFIED_INTACT"


def test_crypto_lab_pcap_omits_packet_contents_and_ciphertext():
    """
    Test PCAP evidence in Crypto Lab:
      Must show ONLY encryption/decryption timing, input/output sizes, and throughput.
      Must NOT display packet contents or ciphertext previews.
    """
    pcap_data = build_test_pcap(packet_count=5)
    filename = "network_capture.pcap"

    upload_resp = upload_secure_evidence(client, pcap_data, filename=filename)
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # 1. Metadata check
    meta = client.get(f"/api/evidence/{ev_id}/crypto-lab").json()
    assert meta["is_pcap"] is True

    # 2. Decrypt execution check
    res = client.post(f"/api/evidence/{ev_id}/crypto-lab/decrypt").json()
    assert res["is_pcap"] is True

    # MUST NOT display packet contents or ciphertext previews
    assert res["plaintext_preview"] is None
    assert res["plaintext_preview_type"] == "binary_omitted"
    assert res["ciphertext_preview_hex"] is None
    assert res["ciphertext_preview_b64"] is None

    # Performance and verification MUST be present
    assert res["gcm_authentication_valid"] is True
    assert res["integrity_status"] == "VERIFIED_INTACT"
    assert res["original_size_bytes"] == len(pcap_data)
    assert res["decryption_duration_ms"] > 0
    assert res["decryption_throughput_mbps"] is not None


def test_crypto_lab_older_evidence_without_timing_handled_gracefully():
    """
    Older evidence items uploaded without encryption timing must return
    recorded_encryption_duration_ms: None ('Not recorded') gracefully.
    """
    text_content = b"Legacy uninstrumented evidence item\n"
    filename = "legacy_item.log"

    packaged, form_data = create_signed_encrypted_payload(content=text_content, filename=filename)
    # Ensure no encryption_duration_ms is sent
    form_data.pop("encryption_duration_ms", None)

    upload_resp = client.post(
        "/api/evidence",
        files={"file": (filename, io.BytesIO(packaged), "application/octet-stream")},
        data=form_data,
    )
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    meta = client.get(f"/api/evidence/{ev_id}/crypto-lab").json()
    assert meta["recorded_encryption_duration_ms"] is None
    assert meta["recorded_encryption_throughput_mbps"] is None

    res = client.post(f"/api/evidence/{ev_id}/crypto-lab/decrypt").json()
    assert res["encryption_duration_ms"] is None
    assert res["decryption_duration_ms"] > 0


def test_crypto_lab_tampered_ciphertext_fails_with_clear_error():
    """
    Tampering with the on-disk ciphertext must cause AES-GCM authentication
    failure (HTTP 422), and content must NOT be exposed as verified.
    """
    text_content = b"Sensitive investigation memorandum\n"
    filename = "tamper_target.txt"

    upload_resp = upload_secure_evidence(client, text_content, filename=filename)
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # Tamper with file on disk
    with SessionLocal() as db:
        ev = db.query(Evidence).filter(Evidence.evidence_id == ev_id).first()
        from pathlib import Path
        disk_path = Path(ev.file_path)
        raw_bytes = bytearray(disk_path.read_bytes())
        # Flip bit in ciphertext region (after 28 bytes of nonce + tag)
        raw_bytes[-1] ^= 0xFF
        disk_path.write_bytes(bytes(raw_bytes))

    dec_resp = client.post(f"/api/evidence/{ev_id}/crypto-lab/decrypt")
    assert dec_resp.status_code == 422
    assert "tag mismatch" in dec_resp.json()["detail"].lower() or "authentication failed" in dec_resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# SHA-256 Hashing Tests
# ---------------------------------------------------------------------------

def test_sha256_evidence_hash_returns_both_representations():
    """
    For an encrypted evidence item, POST /{evidence_id}/crypto-lab/hash
    must compute hashes for both the raw encrypted container on disk and the
    authenticated decrypted plaintext, matching the acquisition hash.
    """
    import hashlib

    text_content = b"ForenSight SHA-256 Laboratory Benchmark Sample Data.\n"
    filename = "sha256_test_evidence.txt"

    upload_resp = upload_secure_evidence(client, text_content, filename=filename)
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]
    expected_plain_digest = hashlib.sha256(text_content).hexdigest()

    resp = client.post(f"/api/evidence/{ev_id}/crypto-lab/hash")
    assert resp.status_code == 200
    data = resp.json()

    assert data["evidence_id"] == ev_id
    assert data["file_name"] == filename
    assert data["is_encrypted"] is True
    assert data["stored_acquisition_hash"] == expected_plain_digest

    hashes = data["hashes"]
    assert len(hashes) == 2

    container_hash = next(h for h in hashes if "container" in h["representation_label"].lower())
    plaintext_hash = next(h for h in hashes if "plaintext" in h["representation_label"].lower())

    assert len(container_hash["sha256_digest"]) == 64
    assert plaintext_hash["sha256_digest"] == expected_plain_digest
    assert plaintext_hash["file_size_bytes"] == len(text_content)
    assert plaintext_hash["throughput_mbps"] >= 0
    assert plaintext_hash["duration_ms"] >= 0
    assert plaintext_hash["is_empty_file"] is False


def test_sha256_evidence_hash_nonexistent_returns_404():
    """Requesting SHA-256 hash for a non-existent evidence artifact returns 404."""
    resp = client.post("/api/evidence/EVD-NONEXISTENT-8888/crypto-lab/hash")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_sha256_standalone_file_hashing():
    """Streaming SHA-256 calculation for uploaded arbitrary file."""
    import hashlib

    test_bytes = b"Arbitrary binary stream for ForenSight SHA-256 standalone test."
    expected_digest = hashlib.sha256(test_bytes).hexdigest()

    resp = client.post(
        "/api/evidence/crypto-lab/hash-file",
        files={"file": ("test_stream.bin", io.BytesIO(test_bytes), "application/octet-stream")},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["file_name"] == "test_stream.bin"
    assert data["file_size_bytes"] == len(test_bytes)
    assert data["sha256_digest"] == expected_digest
    assert data["throughput_mbps"] >= 0
    assert data["duration_ms"] >= 0
    assert data["chunks_processed"] == 1
    assert data["is_empty_file"] is False


def test_sha256_standalone_empty_file():
    """
    Hashing a 0-byte file must safely yield the standard NIST SHA-256 digest
    without division-by-zero or failure.
    """
    nist_empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    resp = client.post(
        "/api/evidence/crypto-lab/hash-file",
        files={"file": ("empty.dat", io.BytesIO(b""), "application/octet-stream")},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["file_size_bytes"] == 0
    assert data["sha256_digest"] == nist_empty_digest
    assert data["is_empty_file"] is True
    assert data["throughput_mbps"] == 0.0


def test_sha256_compare_identical_files():
    """Comparing identical files results in 100% match and 0 bit difference."""
    data_content = b"Exact identical forensic message string.\n"

    resp = client.post(
        "/api/evidence/crypto-lab/hash-compare",
        files={
            "file_a": ("doc_a.txt", io.BytesIO(data_content), "text/plain"),
            "file_b": ("doc_b.txt", io.BytesIO(data_content), "text/plain"),
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["digests_match"] is True
    assert data["hex_character_differences"] == 0
    assert data["bit_differences"] == 0
    assert data["avalanche_percentage"] == 0.0
    assert data["input_a_digest"] == data["input_b_digest"]


def test_sha256_compare_avalanche_effect():
    """
    Comparing two files differing by a single character demonstrates the avalanche effect
    (divergence in ~50% of the 256 bits).
    """
    msg_a = b"The quick brown fox jumps over the lazy dog."
    msg_b = b"The quick brown fox jumps over the lazy cog."

    resp = client.post(
        "/api/evidence/crypto-lab/hash-compare",
        files={
            "file_a": ("input_a.txt", io.BytesIO(msg_a), "text/plain"),
            "file_b": ("input_b.txt", io.BytesIO(msg_b), "text/plain"),
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["digests_match"] is False
    assert data["hex_character_differences"] > 30
    assert data["bit_differences"] > 80
    assert data["avalanche_percentage"] > 30.0
    assert "avalanche effect" in data["educational_note"].lower()

