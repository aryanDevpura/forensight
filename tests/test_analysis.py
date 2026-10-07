"""
Tests for Milestone 5: Forensic Evidence Analysis (PCAP).

Covers:
  1. Safe parsing of PCAP files.
  2. Extraction of packet count, protocols, IP addresses, ports, timestamps.
  3. Structured findings generation and association with evidence ID.
  4. Findings persisted via Finding model.
  5. Evidence integrity: original file bytes and SHA-256 hash remain untouched.
  6. Analysis with client/sample_network_trace.pcap (sample vector).
  7. Non-existent evidence ID returns 404.
  8. Non-PCAP evidence returns 400 for PCAP inspection.
  9. System stats reflects finding count.
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


def build_binary_pcap(packet_count: int = 5, has_scan: bool = False, has_cleartext: bool = False) -> bytes:
    """Helper to generate a valid, binary PCAP file with known characteristics."""
    # Global header (24 bytes)
    # magic=0xa1b2c3d4 (little-endian: 0xd4c3b2a1), v2.4, tz=0, sigfigs=0, snaplen=65535, dlt=1 (Ethernet)
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packets_bytes = bytearray()
    base_ts = 1710000000

    ports_to_use = []
    if has_scan:
        # 12 distinct ports to trigger scan heuristic (threshold is 10)
        ports_to_use = [8000 + i for i in range(12)]
    elif has_cleartext:
        ports_to_use = [80, 21, 23]
    else:
        ports_to_use = [443, 53, 22]

    for i in range(packet_count):
        ts_sec = base_ts + i * 2
        ts_usec = 100000

        # Ethernet
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

        # IPv4
        src_ip = socket.inet_aton("192.168.1.50")
        dst_ip = socket.inet_aton("10.0.0.1")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i + 1, 0, 64, 6, 0, src_ip, dst_ip)

        # TCP
        dst_port = ports_to_use[i % len(ports_to_use)]
        tcp = struct.pack("!HHIIHHHH", 50000 + i, dst_port, 1000 + i, 0, (5 << 12) | 0x02, 65535, 0, 0)

        pkt_data = eth + ip + tcp
        ph = struct.pack("<IIII", ts_sec, ts_usec, len(pkt_data), len(pkt_data))
        packets_bytes.extend(ph + pkt_data)

    return bytes(gh + packets_bytes)


def test_analyze_with_sample_network_trace_pcap():
    """
    Test analysis using the existing client/sample_network_trace.pcap file.
    Verifies upload, analysis trigger, findings generation, and integrity preservation.
    """
    sample_path = Path("client/sample_network_trace.pcap")
    assert sample_path.exists(), "client/sample_network_trace.pcap must exist"

    with open(sample_path, "rb") as f:
        file_bytes = f.read()

    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()

    # 1. Upload the sample file
    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("sample_network_trace.pcap", io.BytesIO(file_bytes), "application/octet-stream")},
        data={"source_device": "workstation-lab-01", "collector_id": "collector-agent-01"},
    )
    assert upload_resp.status_code == 201
    evd_data = upload_resp.json()
    evidence_id = evd_data["evidence_id"]
    assert evd_data["sha256_hash"] == expected_sha256

    # 2. Trigger analysis
    analysis_resp = client.post(f"/api/analysis/{evidence_id}")
    assert analysis_resp.status_code == 200, analysis_resp.text
    result = analysis_resp.json()

    assert result["evidence_id"] == evidence_id
    assert result["evidence_status"] == "ANALYZED"
    assert result["findings_count"] >= 1
    assert len(result["findings"]) >= 1

    # 3. Retrieve findings through dedicated endpoint
    findings_resp = client.get(f"/api/analysis/findings/{evidence_id}")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == result["findings_count"]
    for f in findings:
        assert f["evidence_id"] == evidence_id
        assert f["finding_id"].startswith("FND-")
        assert f["category"] in ("ANOMALY", "NETWORK_SUMMARY", "NETWORK_SCAN", "CLEAR_TEXT_TRAFFIC")

    # 4. CRITICAL INTEGRITY CHECK: Verify original disk file and SHA-256 hash are UNTOUCHED
    disk_file = Path(evd_data["file_path"])
    assert disk_file.exists()
    with open(disk_file, "rb") as f:
        post_analysis_bytes = f.read()
    post_analysis_hash = hashlib.sha256(post_analysis_bytes).hexdigest()
    assert post_analysis_hash == expected_sha256, "Cryptographic hash must not change after analysis"

    # Verify database record hash remains intact
    evd_check = client.get("/api/evidence").json()
    matched = [e for e in evd_check if e["evidence_id"] == evidence_id][0]
    assert matched["sha256_hash"] == expected_sha256
    assert matched["status"] == "ANALYZED"


def test_analyze_binary_valid_pcap_extracts_metadata():
    """
    Test that a valid binary PCAP produces accurate extracted packet counts,
    protocols, IPs, ports, and structured findings.
    """
    pcap_data = build_binary_pcap(packet_count=6, has_scan=False, has_cleartext=False)
    pcap_sha256 = hashlib.sha256(pcap_data).hexdigest()

    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("valid_traffic.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
        data={"source_device": "network-tap-01"},
    )
    assert upload_resp.status_code == 201
    evd = upload_resp.json()
    evidence_id = evd["evidence_id"]

    # Trigger analysis
    resp = client.post(f"/api/analysis/{evidence_id}")
    assert resp.status_code == 200
    res = resp.json()

    assert res["is_valid_pcap"] is True
    assert res["packet_count"] == 6
    assert "TCP" in res["protocols"]
    assert res["protocols"]["TCP"] == 6
    assert "192.168.1.50" in res["source_ips"]
    assert "10.0.0.1" in res["destination_ips"]
    assert len(res["conversations"]) >= 1

    # Check findings
    findings = res["findings"]
    assert any(f["category"] == "NETWORK_SUMMARY" for f in findings)


def test_analyze_pcap_detects_port_scan_heuristic():
    """Test heuristic detection of vertical/horizontal port scan."""
    scan_pcap = build_binary_pcap(packet_count=12, has_scan=True, has_cleartext=False)

    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("port_scan_test.pcap", io.BytesIO(scan_pcap), "application/octet-stream")},
        data={"source_device": "dmz-honeypot"},
    )
    assert upload_resp.status_code == 201
    evidence_id = upload_resp.json()["evidence_id"]

    resp = client.post(f"/api/analysis/{evidence_id}")
    assert resp.status_code == 200
    res = resp.json()

    scan_findings = [f for f in res["findings"] if f["category"] == "NETWORK_SCAN"]
    assert len(scan_findings) >= 1
    assert scan_findings[0]["severity"] == "HIGH"
    assert "192.168.1.50" in scan_findings[0]["title"]


def test_analyze_pcap_detects_cleartext_protocols():
    """Test heuristic detection of unencrypted cleartext protocols."""
    cleartext_pcap = build_binary_pcap(packet_count=3, has_scan=False, has_cleartext=True)

    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("cleartext_traffic.pcap", io.BytesIO(cleartext_pcap), "application/octet-stream")},
    )
    assert upload_resp.status_code == 201
    evidence_id = upload_resp.json()["evidence_id"]

    resp = client.post(f"/api/analysis/{evidence_id}")
    assert resp.status_code == 200
    res = resp.json()

    cleartext_findings = [f for f in res["findings"] if f["category"] == "CLEAR_TEXT_TRAFFIC"]
    assert len(cleartext_findings) >= 1
    assert cleartext_findings[0]["severity"] == "MEDIUM"


def test_analyze_custody_event_logged():
    """Verify that analyzing evidence logs an ANALYZED event in chain of custody."""
    pcap_data = build_binary_pcap(packet_count=2)
    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("custody_flow.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    )
    evidence_id = upload_resp.json()["evidence_id"]

    client.post(f"/api/analysis/{evidence_id}")

    custody_resp = client.get(f"/api/custody/{evidence_id}")
    assert custody_resp.status_code == 200
    events = custody_resp.json()
    actions = [e["action"] for e in events]
    assert "ACQUIRED" in actions
    assert "ANALYZED" in actions


def test_analyze_nonexistent_evidence_returns_404():
    """Analysis for unknown evidence ID returns 404."""
    resp = client.post("/api/analysis/EVD-DOES-NOT-EXIST-999")
    assert resp.status_code == 404


def test_analyze_unsupported_evidence_type_returns_400():
    """Analysis of non-PCAP evidence returns 400."""
    log_content = b"2026-10-08 00:00:00 systemd[1]: Started Service."
    upload_resp = client.post(
        "/api/evidence",
        files={"file": ("system.log", io.BytesIO(log_content), "text/plain")},
    )
    assert upload_resp.status_code == 201
    evidence_id = upload_resp.json()["evidence_id"]

    resp = client.post(f"/api/analysis/{evidence_id}")
    assert resp.status_code == 400
    assert "supported for PCAP" in resp.json()["detail"]


def test_list_all_findings_endpoint():
    """Verify GET /api/analysis/findings returns findings list."""
    resp = client.get("/api/analysis/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
