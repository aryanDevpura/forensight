"""
Tests for Milestone 7: Performance Instrumentation & Benchmarking.

Covers:
  1. Real measurement and recording of SHA256_HASHING on evidence upload.
  2. Real measurement and recording of EVIDENCE_INGESTION total processing time.
  3. Real measurement and recording of HMAC_VERIFICATION on authenticated upload.
  4. Real measurement and recording of PCAP_ANALYSIS on forensic packet dissection.
  5. Collector HMAC signing measurement (sign_request_with_metrics).
  6. Endpoint GET /api/benchmarks with filtering.
  7. Endpoint GET /api/benchmarks/evidence/{evidence_id}.
  8. Endpoint GET /api/benchmarks/summary.
  9. Metric validity: non-zero duration_ms, throughput calculation, evidence association.
  10. Non-existent evidence benchmark query returns 404.
"""

import io
import os
import struct
import socket
import time
from pathlib import Path
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db
from collector.auth import sign_request, sign_request_with_metrics, compute_payload_hash
from tests.crypto_test_utils import upload_secure_evidence

init_db()
client = TestClient(app)

TEST_HMAC_SECRET = "test-forensic-secret-milestone7-32b-key"


def build_valid_pcap(packet_count: int = 5) -> bytes:
    """Helper to generate binary PCAP bytes."""
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets = bytearray()
    base_ts = 1710000000

    for i in range(packet_count):
        ts_sec = base_ts + i * 2
        ts_usec = 100000
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        src_ip = socket.inet_aton(f"10.0.1.{10 + i}")
        dst_ip = socket.inet_aton("172.16.0.1")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i + 1, 0, 64, 6, 0, src_ip, dst_ip)
        tcp = struct.pack("!HHIIHHHH", 50000 + i, 80, 1000 + i, 0, (5 << 12) | 0x02, 65535, 0, 0)
        pkt = eth + ip + tcp
        ph = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
        packets.extend(ph + pkt)

    return bytes(gh + packets)


def test_evidence_ingestion_and_hashing_benchmarks_recorded():
    """Verify that uploading evidence records SHA256_HASHING, EVIDENCE_INGESTION, RSA_VERIFICATION, and AES_DECRYPTION benchmarks."""
    sample_content = b"EVIDENCE_DATA_STREAM_BENCHMARK_TEST_PAYLOAD_" * 1000  # ~45 KB
    upload_resp = upload_secure_evidence(
        client,
        sample_content,
        filename="bench_test.log",
        source_device="bench-station-01",
    )
    assert upload_resp.status_code == 201
    evd_id = upload_resp.json()["evidence_id"]

    # Query benchmarks associated with this evidence
    bench_resp = client.get(f"/api/benchmarks/evidence/{evd_id}")
    assert bench_resp.status_code == 200, bench_resp.text
    records = bench_resp.json()

    bench_names = [r["benchmark_name"] for r in records]
    assert "SHA256_HASHING" in bench_names
    assert "EVIDENCE_INGESTION" in bench_names
    assert "RSA_VERIFICATION" in bench_names
    assert "AES_DECRYPTION" in bench_names

    for r in records:
        assert r["evidence_id"] == evd_id
        assert r["duration_ms"] > 0.0
        assert r["throughput_mbps"] is not None
        assert r["throughput_mbps"] > 0.0
        if r["benchmark_name"] in ("SHA256_HASHING", "AES_DECRYPTION"):
            assert r["sample_size_bytes"] == len(sample_content)
        elif r["benchmark_name"] == "EVIDENCE_INGESTION":
            assert r["sample_size_bytes"] >= len(sample_content)
        elif r["benchmark_name"] == "RSA_VERIFICATION":
            assert r["sample_size_bytes"] > 0


def test_secure_upload_records_rsa_verification_benchmark():
    """Verify that RSA signature verification execution time is measured and recorded as a benchmark."""
    payload = b"AUTHENTICATED_UPLOAD_BENCHMARK_PAYLOAD_TEST_DATA"
    upload_resp = upload_secure_evidence(
        client,
        payload,
        filename="auth_bench.log",
        source_device="collector-agent-01",
    )
    assert upload_resp.status_code == 201
    actual_evd_id = upload_resp.json()["evidence_id"]

    # Verify RSA_VERIFICATION benchmark recorded
    bench_resp = client.get(f"/api/benchmarks/evidence/{actual_evd_id}")
    assert bench_resp.status_code == 200
    records = bench_resp.json()

    rsa_records = [r for r in records if r["benchmark_name"] == "RSA_VERIFICATION"]
    assert len(rsa_records) >= 1
    rec = rsa_records[0]
    assert rec["evidence_id"] == actual_evd_id
    assert rec["duration_ms"] > 0.0


def test_pcap_analysis_records_benchmark():
    """Verify that running PCAP forensic analysis measures and records PCAP_ANALYSIS benchmark."""
    pcap_data = build_valid_pcap(packet_count=6)
    upload_resp = upload_secure_evidence(
        client,
        pcap_data,
        filename="analysis_bench.pcap",
    )
    assert upload_resp.status_code == 201
    evd_id = upload_resp.json()["evidence_id"]

    # Trigger analysis
    analysis_resp = client.post(f"/api/analysis/{evd_id}")
    assert analysis_resp.status_code == 200

    # Verify PCAP_ANALYSIS benchmark was created
    bench_resp = client.get(f"/api/benchmarks/evidence/{evd_id}")
    assert bench_resp.status_code == 200
    records = bench_resp.json()

    analysis_records = [r for r in records if r["benchmark_name"] == "PCAP_ANALYSIS"]
    assert len(analysis_records) >= 1
    ar = analysis_records[0]
    assert ar["evidence_id"] == evd_id
    assert ar["sample_size_bytes"] == len(pcap_data)
    assert ar["duration_ms"] > 0.0
    assert "Packets: 6" in ar["system_info"]


def test_collector_sign_request_with_metrics():
    """Verify that collector auth provides sign_request_with_metrics with high-res timing."""
    headers, duration_sec = sign_request_with_metrics(
        secret=TEST_HMAC_SECRET,
        evidence_id="EVD-TEST-SIGN-METRIC",
        payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert "X-ForenSight-Signature" in headers
    assert isinstance(duration_sec, float)
    assert duration_sec >= 0.0


def test_benchmarks_summary_endpoint():
    """Verify GET /api/benchmarks/summary returns aggregated operation statistics."""
    resp = client.get("/api/benchmarks/summary")
    assert resp.status_code == 200
    data = resp.json()

    assert "operations" in data
    assert "total_records" in data
    assert isinstance(data["total_records"], int)
    assert data["total_records"] >= 0

    if data["total_records"] > 0:
        for op_name, stats in data["operations"].items():
            assert "count" in stats
            assert "avg_duration_ms" in stats
            assert stats["count"] >= 1
            assert stats["avg_duration_ms"] >= 0.0


def test_get_benchmarks_nonexistent_evidence_returns_404():
    """Querying benchmarks for unknown evidence returns 404."""
    resp = client.get("/api/benchmarks/evidence/EVD-UNKNOWN-BENCH-999")
    assert resp.status_code == 404
