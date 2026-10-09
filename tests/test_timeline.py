"""
Tests for Milestone 6: Forensic Timeline & Event Correlation.

Covers:
  1. Automatic generation of chronological forensic events upon PCAP analysis.
  2. Association of every forensic event with the target evidence_id.
  3. Inclusion of detailed network flow metadata (source/destination IP, ports, protocol)
     and security finding metadata.
  4. Retrieval via GET /api/timeline/{evidence_id} ordered strictly chronologically.
  5. Error handling: non-existent evidence_id returns 404.
  6. Idempotency: re-analyzing evidence refreshes events without duplicate accumulation.
  7. Evidence integrity and chain of custody preservation: original disk file hash untouched.
"""

import hashlib
import io
import json
import struct
import socket
from datetime import datetime
from pathlib import Path
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db

init_db()
client = TestClient(app)


def build_test_pcap(packet_count: int = 4) -> bytes:
    """Helper to build a valid binary PCAP with distinct timestamps and flows."""
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets = bytearray()
    base_ts = 1710000000

    for i in range(packet_count):
        ts_sec = base_ts + i * 10
        ts_usec = 250000

        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        src_ip = socket.inet_aton(f"192.168.1.{10 + i}")
        dst_ip = socket.inet_aton("10.0.0.5")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i + 1, 0, 64, 6, 0, src_ip, dst_ip)

        src_port = 40000 + i
        dst_port = 80 if i % 2 == 0 else 443
        tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1000 + i, 0, (5 << 12) | 0x02, 65535, 0, 0)

        pkt = eth + ip + tcp
        ph = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
        packets.extend(ph + pkt)

    return bytes(gh + packets)


def test_timeline_events_generated_on_analysis():
    """Verify that analyzing PCAP creates associated timeline events with network metadata."""
    pcap_data = build_test_pcap(packet_count=4)
    expected_hash = hashlib.sha256(pcap_data).hexdigest()

    # 1. Upload evidence
    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("timeline_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
        data={"source_device": "network-gateway-01", "collector_id": "collector-agent-01"},
    )
    assert upload_resp.status_code == 201
    evidence_id = upload_resp.json()["evidence_id"]
    file_path = upload_resp.json()["file_path"]

    # 2. Trigger analysis
    analysis_resp = client.post(f"/api/analysis/{evidence_id}")
    assert analysis_resp.status_code == 200

    # 3. Fetch timeline events
    timeline_resp = client.get(f"/api/timeline/{evidence_id}")
    assert timeline_resp.status_code == 200, timeline_resp.text
    events = timeline_resp.json()

    assert len(events) >= 4, "Must generate timeline events for packets and findings"

    # Verify event fields and evidence association
    for ev in events:
        assert ev["evidence_id"] == evidence_id
        assert ev["event_id"].startswith("EVT-")
        assert ev["event_type"] in ("NETWORK_FLOW", "SECURITY_FINDING")
        assert ev["timestamp"] is not None

        if ev["event_type"] == "NETWORK_FLOW":
            assert ev["metadata_json"] is not None
            meta = json.loads(ev["metadata_json"])
            assert "source_ip" in meta
            assert "destination_ip" in meta
            assert meta["protocol"] == "TCP"
            assert "source_port" in meta
            assert "destination_port" in meta

    # 4. Verify strictly chronological ordering
    timestamps = [datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")) for ev in events]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1], "Timeline events must be ordered chronologically (oldest first)"

    # 5. Verify physical evidence integrity preserved
    disk_file = Path(file_path)
    assert disk_file.exists()
    disk_bytes = disk_file.read_bytes()
    if upload_resp.json().get("is_encrypted"):
        from server.app.core.crypto import decrypt_payload
        from server.app.core.config import settings
        decrypted_bytes, _ = decrypt_payload(disk_bytes, settings.FORENSIGHT_ENCRYPTION_KEY)
        post_hash = hashlib.sha256(decrypted_bytes).hexdigest()
    else:
        post_hash = hashlib.sha256(disk_bytes).hexdigest()
    assert post_hash == expected_hash, "Original file hash must remain unchanged"


def test_timeline_nonexistent_evidence_returns_404():
    """Querying timeline for nonexistent evidence ID returns 404."""
    resp = client.get("/api/timeline/EVD-UNKNOWN-99999")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_timeline_isolated_between_multiple_evidence():
    """Verify that timeline queries only return events belonging to the requested evidence ID."""
    pcap_1 = build_test_pcap(packet_count=2)
    pcap_2 = build_test_pcap(packet_count=3)

    up1 = client.post(
        "/api/evidence",
        files={"file": ("trace_one.pcap", io.BytesIO(pcap_1), "application/octet-stream")},
    ).json()
    up2 = client.post(
        "/api/evidence",
        files={"file": ("trace_two.pcap", io.BytesIO(pcap_2), "application/octet-stream")},
    ).json()

    id1 = up1["evidence_id"]
    id2 = up2["evidence_id"]

    client.post(f"/api/analysis/{id1}")
    client.post(f"/api/analysis/{id2}")

    t1 = client.get(f"/api/timeline/{id1}").json()
    t2 = client.get(f"/api/timeline/{id2}").json()

    assert all(e["evidence_id"] == id1 for e in t1)
    assert all(e["evidence_id"] == id2 for e in t2)


def test_timeline_idempotency_on_reanalysis():
    """Re-analyzing an evidence item should refresh events without leaking duplicates."""
    pcap_data = build_test_pcap(packet_count=3)
    evd = client.post(
        "/api/evidence",
        files={"file": ("idempotency.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    ).json()
    evd_id = evd["evidence_id"]

    client.post(f"/api/analysis/{evd_id}")
    count1 = len(client.get(f"/api/timeline/{evd_id}").json())

    # Re-run analysis
    client.post(f"/api/analysis/{evd_id}")
    count2 = len(client.get(f"/api/timeline/{evd_id}").json())

    assert count1 == count2, "Re-analysis should be idempotent regarding timeline events"
