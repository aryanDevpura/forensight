"""
Tests for post-acquisition evidence integrity verification.

Covers:
  1. Intact file: verify returns INTACT with matching hashes.
  2. Modified file: verify detects hash mismatch and returns TAMPERED.
  3. Missing file: verify returns FILE_MISSING (not 404) for a known evidence ID.
  4. Unknown ID: verify returns HTTP 404.
  5. Custody events: every verify call writes an INTEGRITY_CHECK custody record.
  6. Original hash preserved: stored hash is never overwritten after tampering.
  7. Analysis blocked on modified evidence: analysis endpoint returns 409.
  8. Analysis succeeds on intact evidence after earlier verify call.
"""

import hashlib
import io
import struct
import socket
from pathlib import Path

from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db

init_db()
client = TestClient(app)


def _build_valid_pcap(packet_count=3):
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets = bytearray()
    base_ts = 1710000000
    src_ip = socket.inet_aton("10.0.0.1")
    dst_ip = socket.inet_aton("10.0.0.2")
    for i in range(packet_count):
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i + 1, 0, 64, 6, 0, src_ip, dst_ip)
        tcp = struct.pack("!HHIIHHHH", 50000 + i, 443, 1000, 0, (5 << 12) | 0x02, 65535, 0, 0)
        pkt = eth + ip + tcp
        ph = struct.pack("<IIII", base_ts + i, 0, len(pkt), len(pkt))
        packets.extend(ph + pkt)
    return bytes(gh + packets)


def _upload_pcap(pcap_bytes, filename="test.pcap"):
    resp = client.post(
        "/api/evidence",
        files={"file": (filename, io.BytesIO(pcap_bytes), "application/octet-stream")},
        data={"source_device": "integrity-test-host"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _verify(evidence_id):
    return client.post(f"/api/evidence/{evidence_id}/verify")


def test_verify_intact_file_returns_intact():
    pcap = _build_valid_pcap(packet_count=4)
    evd = _upload_pcap(pcap, filename="intact_check.pcap")
    evidence_id = evd["evidence_id"]
    stored_hash = evd["sha256_hash"]
    resp = _verify(evidence_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["evidence_id"] == evidence_id
    assert body["is_intact"] is True
    assert body["status"] == "INTACT"
    assert body["stored_hash"] == stored_hash
    assert body["current_hash"] == stored_hash
    assert "intact" in body["message"].lower()


def test_verify_modified_file_returns_tampered():
    pcap = _build_valid_pcap(packet_count=5)
    evd = _upload_pcap(pcap, filename="tamper_target.pcap")
    evidence_id = evd["evidence_id"]
    stored_hash = evd["sha256_hash"]
    disk_path = Path(evd["file_path"])
    assert disk_path.exists()
    original_bytes = disk_path.read_bytes()
    tampered_bytes = original_bytes[:-4] + b"\xDE\xAD\xBE\xEF"
    disk_path.write_bytes(tampered_bytes)
    try:
        resp = _verify(evidence_id)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["evidence_id"] == evidence_id
        assert body["is_intact"] is False
        assert body["status"] == "TAMPERED"
        assert body["stored_hash"] == stored_hash
        assert body["current_hash"] is not None
        assert body["current_hash"] != stored_hash
        expected_tampered_hash = hashlib.sha256(tampered_bytes).hexdigest()
        assert body["current_hash"] == expected_tampered_hash
    finally:
        disk_path.write_bytes(original_bytes)


def test_verify_missing_file_returns_file_missing():
    pcap = _build_valid_pcap(packet_count=2)
    evd = _upload_pcap(pcap, filename="delete_me.pcap")
    evidence_id = evd["evidence_id"]
    stored_hash = evd["sha256_hash"]
    disk_path = Path(evd["file_path"])
    assert disk_path.exists()
    disk_path.unlink()
    # No teardown: the file was legitimately deleted as part of this test.
    # The DB record deliberately retains the stored hash pointing to a now-absent file.

    resp = _verify(evidence_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["evidence_id"] == evidence_id
    assert body["is_intact"] is False
    assert body["status"] == "FILE_MISSING"
    assert body["stored_hash"] == stored_hash
    assert body["current_hash"] is None
    assert "missing" in body["message"].lower()


def test_verify_unknown_evidence_id_returns_404():
    resp = client.post("/api/evidence/EVD-DOES-NOT-EXIST-XYZ-999/verify")
    assert resp.status_code == 404
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower()


def test_verify_records_custody_event():
    pcap = _build_valid_pcap(packet_count=2)
    evd = _upload_pcap(pcap, filename="custody_verify.pcap")
    evidence_id = evd["evidence_id"]
    _verify(evidence_id)
    disk_path = Path(evd["file_path"])
    original = disk_path.read_bytes()
    disk_path.write_bytes(original + b"\xFF")
    try:
        _verify(evidence_id)
    finally:
        disk_path.write_bytes(original)
    custody_resp = client.get(f"/api/custody/{evidence_id}")
    assert custody_resp.status_code == 200
    events = custody_resp.json()
    integrity_events = [e for e in events if e["action"] == "INTEGRITY_CHECK"]
    assert len(integrity_events) >= 2
    notes_combined = " ".join(e["notes"] for e in integrity_events)
    assert "PASSED" in notes_combined
    assert "FAILED" in notes_combined


def test_verify_never_overwrites_stored_hash():
    pcap = _build_valid_pcap()
    evd = _upload_pcap(pcap, filename="hash_preserve.pcap")
    evidence_id = evd["evidence_id"]
    original_stored_hash = evd["sha256_hash"]
    disk_path = Path(evd["file_path"])
    original_bytes = disk_path.read_bytes()
    disk_path.write_bytes(b"COMPLETELY_REPLACED_CONTENT")
    try:
        _verify(evidence_id)
    finally:
        disk_path.write_bytes(original_bytes)
    evd_list = client.get("/api/evidence").json()
    record = next((e for e in evd_list if e["evidence_id"] == evidence_id), None)
    assert record is not None
    assert record["sha256_hash"] == original_stored_hash


def test_analysis_blocked_on_tampered_evidence():
    pcap = _build_valid_pcap(packet_count=3)
    evd = _upload_pcap(pcap, filename="block_on_tamper.pcap")
    evidence_id = evd["evidence_id"]
    disk_path = Path(evd["file_path"])
    original_bytes = disk_path.read_bytes()
    disk_path.write_bytes(b"TAMPERED_PCAP_CONTENT_THAT_CHANGES_HASH")
    try:
        resp = client.post(f"/api/analysis/{evidence_id}")
        assert resp.status_code == 409, (
            f"Expected 409, got {resp.status_code}: {resp.text}"
        )
        detail = resp.json().get("detail", "")
        assert "integrity" in detail.lower() or "hash" in detail.lower()
    finally:
        disk_path.write_bytes(original_bytes)


def test_analysis_succeeds_on_intact_evidence_after_verify():
    pcap = _build_valid_pcap(packet_count=4)
    evd = _upload_pcap(pcap, filename="analyze_after_verify.pcap")
    evidence_id = evd["evidence_id"]
    verify_resp = _verify(evidence_id)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_intact"] is True
    analysis_resp = client.post(f"/api/analysis/{evidence_id}")
    assert analysis_resp.status_code == 200, analysis_resp.text
    result = analysis_resp.json()
    assert result["evidence_id"] == evidence_id
    assert result["evidence_status"] == "ANALYZED"
    assert result["findings_count"] >= 1


def test_analysis_missing_file_returns_500():
    """
    If the on-disk evidence file is deleted after acquisition, the analysis
    endpoint must return HTTP 500 (file not found) rather than masking the
    problem with a type-check 400 or running on ghost data.
    The integrity pre-check in analysis.py must catch this before type validation.
    """
    pcap = _build_valid_pcap(packet_count=2)
    evd = _upload_pcap(pcap, filename="missing_for_analysis.pcap")
    evidence_id = evd["evidence_id"]
    disk_path = Path(evd["file_path"])
    assert disk_path.exists()
    disk_path.unlink()
    # No teardown: file is gone; the DB record remains as evidence of the gap.

    resp = client.post(f"/api/analysis/{evidence_id}")
    assert resp.status_code == 500, (
        f"Expected 500 for missing evidence file, got {resp.status_code}: {resp.text}"
    )
    detail = resp.json().get("detail", "")
    assert "not found" in detail.lower() or "missing" in detail.lower(), (
        f"500 detail should mention file not found, got: {detail!r}"
    )


def test_analysis_blocked_on_tampered_non_pcap_evidence():
    """
    Integrity guard must fire BEFORE the evidence-type check.
    Uploading a .log file and tampering it on disk must yield HTTP 409
    (hash mismatch detected), not HTTP 400 (unsupported type), because
    the integrity failure is a more urgent condition than the type limitation.
    An un-tampered .log file should still yield 400 as before.
    """
    log_content = b"2026-01-01 00:00:00 kernel: system started"
    # Upload a valid .log file
    resp_upload = client.post(
        "/api/evidence",
        files={"file": ("syslog.log", io.BytesIO(log_content), "text/plain")},
        data={"source_device": "integrity-test-host"},
    )
    assert resp_upload.status_code == 201, resp_upload.text
    evd = resp_upload.json()
    evidence_id = evd["evidence_id"]
    disk_path = Path(evd["file_path"])

    # --- Sanity check: un-tampered .log returns 400 (type not supported) ---
    resp_untampered = client.post(f"/api/analysis/{evidence_id}")
    assert resp_untampered.status_code == 400, (
        f"Un-tampered .log should return 400 (unsupported type), "
        f"got {resp_untampered.status_code}: {resp_untampered.text}"
    )

    # --- Tamper the file on disk ---
    original_bytes = disk_path.read_bytes()
    disk_path.write_bytes(b"TAMPERED LOG CONTENT CHANGING THE HASH")
    try:
        resp_tampered = client.post(f"/api/analysis/{evidence_id}")
        assert resp_tampered.status_code == 409, (
            f"Tampered .log should return 409 (integrity guard before type check), "
            f"got {resp_tampered.status_code}: {resp_tampered.text}"
        )
        detail = resp_tampered.json().get("detail", "")
        assert "integrity" in detail.lower() or "hash" in detail.lower(), (
            f"409 detail should describe integrity failure, got: {detail!r}"
        )
    finally:
        disk_path.write_bytes(original_bytes)
