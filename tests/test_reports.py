"""
Tests for ForenSight Single-Purpose Forensic Evidence Report Generator
======================================================================
Covers:
  1. Evidence report generation for analyzed PCAP (with packet statistics & findings).
  2. Evidence report for unanalyzed evidence (clearly marked NOT_ANALYZED).
  3. Evidence report for non-PCAP evidence (clearly marked NOT_APPLICABLE).
  4. Validation: missing evidence_id is rejected.
  5. Error handling: non-existent evidence_id returns HTTP 404.
  6. PDF download returns genuine application/pdf with %PDF- header.
  7. Report history listing and individual report retrieval.
  8. De-duplication guard: rapid identical requests return existing report without duplication.
  9. Security constraint: reports never expose private keys or secret credentials.
"""

import json
from pathlib import Path
from fastapi.testclient import TestClient

from server.app.main import app
from server.app.database.session import init_db
from tests.crypto_test_utils import upload_secure_evidence
from tests.test_timeline import build_test_pcap

init_db()
client = TestClient(app)


def test_generate_evidence_report_analyzed_pcap():
    """Generates an evidence report for an analyzed PCAP with verified findings."""
    pcap_data = build_test_pcap(packet_count=5)
    upload_resp = upload_secure_evidence(
        client,
        pcap_data,
        filename="report_test_traffic.pcap",
        source_device="perimeter-fw-01",
    )
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # Analyze PCAP
    analysis_resp = client.post(f"/api/analysis/{ev_id}")
    assert analysis_resp.status_code == 200

    # Generate evidence report
    report_resp = client.post(
        "/api/reports",
        json={
            "evidence_id": ev_id,
            "title": "Analyzed Traffic Forensic Report",
            "examiner_name": "Senior Investigator",
            "notes": "Targeted traffic anomaly examination.",
        },
    )
    assert report_resp.status_code == 201, report_resp.text
    r_data = report_resp.json()

    assert r_data["report_scope"] == "EVIDENCE"
    assert r_data["evidence_id"] == ev_id
    assert r_data["file_size_bytes"] > 0
    assert r_data["download_url"] == f"/api/reports/{r_data['report_id']}/download"

    s = r_data["summary_data"]
    assert s["evidence"]["evidence_id"] == ev_id
    assert s["cryptography"]["integrity_status"] == "VERIFIED_INTACT"
    assert s["cryptography"]["is_encrypted"] is True
    assert s["cryptography"]["has_signature"] is True
    assert s["analysis"]["status"] == "ANALYZED"
    assert s["analysis"]["is_pcap"] is True
    assert s["analysis"]["findings_count"] >= 1
    assert len(s["custody"]) >= 1

    # Verify physical PDF file exists on disk and has %PDF- magic bytes
    pdf_path = Path(r_data["file_path"])
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-")


def test_generate_evidence_report_unanalyzed_evidence():
    """Unanalyzed evidence report must explicitly state NOT_ANALYZED without fabricated data."""
    pcap_data = build_test_pcap(packet_count=2)
    upload_resp = upload_secure_evidence(client, pcap_data, filename="unanalyzed.pcap")
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    # Generate report WITHOUT running analysis
    report_resp = client.post(
        "/api/reports",
        json={"evidence_id": ev_id},
    )
    assert report_resp.status_code == 201
    s = report_resp.json()["summary_data"]

    assert s["analysis"]["status"] == "NOT_ANALYZED"
    assert s["analysis"]["findings"] == []
    assert s["analysis"]["packet_stats"] is None
    assert "pending" in s["analysis"]["message"].lower() or "not been initiated" in s["analysis"]["message"].lower()


def test_generate_evidence_report_non_pcap():
    """Non-PCAP evidence report must accurately report NOT_APPLICABLE for packet inspection."""
    log_content = b"2026-10-29T12:00:00Z auth.log: Accepted publickey for examiner\n" * 4
    upload_resp = upload_secure_evidence(client, log_content, filename="auth_audit.log")
    assert upload_resp.status_code == 201
    ev_id = upload_resp.json()["evidence_id"]

    report_resp = client.post(
        "/api/reports",
        json={"evidence_id": ev_id},
    )
    assert report_resp.status_code == 201
    s = report_resp.json()["summary_data"]

    assert s["analysis"]["status"] == "NOT_APPLICABLE"
    assert "not applicable" in s["analysis"]["message"].lower()
    assert s["analysis"]["findings"] == []


def test_generate_evidence_report_missing_evidence_id_fails():
    """Requesting a report without an evidence_id must be rejected."""
    resp = client.post(
        "/api/reports",
        json={"title": "No Evidence Specified"},
    )
    assert resp.status_code in (400, 422)


def test_generate_evidence_report_nonexistent_returns_404():
    """Requesting a report for a non-existent evidence ID must return 404."""
    resp = client.post(
        "/api/reports",
        json={"evidence_id": "EVD-NONEXISTENT-999"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_download_report_pdf():
    """Downloading report PDF returns HTTP 200 with application/pdf and %PDF- bytes."""
    pcap_data = build_test_pcap(packet_count=2)
    ev_id = upload_secure_evidence(client, pcap_data, filename="dl_test.pcap").json()["evidence_id"]

    create_resp = client.post(
        "/api/reports",
        json={"evidence_id": ev_id, "title": "Download Test Report"},
    )
    assert create_resp.status_code == 201
    report_id = create_resp.json()["report_id"]

    # Download PDF
    dl_resp = client.get(f"/api/reports/{report_id}/download")
    assert dl_resp.status_code == 200
    assert "application/pdf" in dl_resp.headers.get("content-type", "")
    assert "attachment" in dl_resp.headers.get("content-disposition", "").lower()
    assert f"{report_id}.pdf" in dl_resp.headers.get("content-disposition", "")
    assert dl_resp.content.startswith(b"%PDF-")
    assert len(dl_resp.content) > 100


def test_list_and_get_reports():
    """Verify listing all reports and retrieving individual report details."""
    list_resp = client.get("/api/reports")
    assert list_resp.status_code == 200
    reports = list_resp.json()
    assert isinstance(reports, list)
    assert len(reports) >= 1

    target_id = reports[0]["report_id"]
    detail_resp = client.get(f"/api/reports/{target_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["report_id"] == target_id
    assert "summary_data" in detail


def test_report_deduplication_on_fast_retry():
    """Fast retries (within 5 seconds) for the same evidence return the existing report."""
    pcap_data = build_test_pcap(packet_count=2)
    ev_id = upload_secure_evidence(client, pcap_data, filename="retry_test.pcap").json()["evidence_id"]

    payload = {"evidence_id": ev_id, "title": "Idempotent Retry Report"}
    resp1 = client.post("/api/reports", json=payload)
    assert resp1.status_code == 201
    id1 = resp1.json()["report_id"]

    resp2 = client.post("/api/reports", json=payload)
    assert resp2.status_code == 201
    id2 = resp2.json()["report_id"]

    assert id1 == id2, "Rapid identical report generation requests must return the existing report"


def test_evidence_list_and_reports_independence():
    """
    Verify that GET /api/evidence returns registered evidence records identically
    and independently from /api/reports. Both endpoints must be reliable and
    coexist without cross-endpoint failure coupling.
    """
    # 1. Fetch evidence items
    ev_resp = client.get("/api/evidence")
    assert ev_resp.status_code == 200
    evidence_list = ev_resp.json()
    assert isinstance(evidence_list, list)
    assert len(evidence_list) >= 1

    # 2. Fetch reports list
    rpt_resp = client.get("/api/reports")
    assert rpt_resp.status_code == 200
    reports_list = rpt_resp.json()
    assert isinstance(reports_list, list)

    # 3. Ensure evidence items retain all core fields required by ReportsPage dropdown
    first_ev = evidence_list[0]
    assert "evidence_id" in first_ev
    assert "file_name" in first_ev
    assert "evidence_type" in first_ev
    assert "file_size_bytes" in first_ev
    assert "status" in first_ev


def test_reports_do_not_expose_secrets():
    """Ensure report metadata, summary payload, and PDF content never expose secret keys."""
    pcap_data = build_test_pcap(packet_count=2)
    ev_id = upload_secure_evidence(client, pcap_data, filename="secret_test.pcap").json()["evidence_id"]

    resp = client.post("/api/reports", json={"evidence_id": ev_id})
    assert resp.status_code == 201
    json_text = json.dumps(resp.json())

    # Check for forbidden sensitive strings
    assert "BEGIN RSA PRIVATE KEY" not in json_text
    assert "BEGIN PRIVATE KEY" not in json_text
    assert "FORENSIGHT_HMAC_SECRET" not in json_text
    assert "FORENSIGHT_ENCRYPTION_KEY" not in json_text

    # Check downloaded PDF bytes
    pdf_bytes = client.get(f"/api/reports/{resp.json()['report_id']}/download").content
    assert b"BEGIN RSA PRIVATE KEY" not in pdf_bytes
    assert b"BEGIN PRIVATE KEY" not in pdf_bytes


def test_download_nonexistent_report_returns_404_json():
    """Downloading a non-existent report must return 404 JSON, not HTML or PDF bytes."""
    resp = client.get("/api/reports/RPT-DOES-NOT-EXIST-9999/download")
    assert resp.status_code == 404
    assert "application/json" in resp.headers.get("content-type", "")
    assert not resp.content.startswith(b"%PDF-")
    assert not resp.content.startswith(b"<!doctype")
    assert "not found" in resp.json().get("detail", "").lower()


def test_download_re_renders_if_file_missing_on_disk():
    """
    If the physical PDF file was removed from storage, GET /api/reports/{id}/download
    must gracefully re-render the PDF from summary_json, persist it back to disk,
    and return valid %PDF- bytes.
    """
    pcap_data = build_test_pcap(packet_count=1)
    ev_id = upload_secure_evidence(client, pcap_data, filename="rerender_test.pcap").json()["evidence_id"]

    create_resp = client.post("/api/reports", json={"evidence_id": ev_id, "title": "Rerender Test"})
    assert create_resp.status_code == 201
    rep_data = create_resp.json()
    rep_id = rep_data["report_id"]
    file_path = Path(rep_data["file_path"])
    assert file_path.exists()

    # Intentionally remove the generated PDF file from disk
    file_path.unlink()
    assert not file_path.exists()

    # Download request should detect missing file and re-render it
    dl_resp = client.get(f"/api/reports/{rep_id}/download")
    assert dl_resp.status_code == 200
    assert "application/pdf" in dl_resp.headers.get("content-type", "")
    assert dl_resp.content.startswith(b"%PDF-")
    # File must be restored on disk
    assert file_path.exists()
    assert file_path.stat().st_size > 100


def test_report_persistence_and_file_existence():
    """Verify that generating a report stores metadata in DB and writes a valid PDF on disk."""
    pcap_data = build_test_pcap(packet_count=2)
    ev_id = upload_secure_evidence(client, pcap_data, filename="persistence_test.pcap").json()["evidence_id"]

    create_resp = client.post(
        "/api/reports",
        json={"evidence_id": ev_id, "title": "Persistence Verification Report"},
    )
    assert create_resp.status_code == 201
    report_meta = create_resp.json()
    report_id = report_meta["report_id"]

    pdf_file = Path(report_meta["file_path"])
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 100
    with open(pdf_file, "rb") as f:
        file_bytes = f.read()
    assert file_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in file_bytes

    # Verify report appears in history
    hist_resp = client.get("/api/reports")
    assert hist_resp.status_code == 200
    matching = [r for r in hist_resp.json() if r["report_id"] == report_id]
    assert len(matching) == 1
    assert matching[0]["file_size_bytes"] == len(file_bytes)

