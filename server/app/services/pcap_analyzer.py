"""
PCAP Forensic Analysis & Finding Generator
==========================================
Coordinates parsing of PCAP evidence, detection of forensic anomalies
(e.g., port scans, unencrypted protocols, anomalous endpoints), and
persistence of structured Finding records linked to the evidence ID.

Integrity guarantee:
  The evidence file on disk is read strictly in read-only mode ('rb').
  The original evidence record and its SHA-256 acquisition hash are never modified.
"""

import hashlib
import json
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from server.app.models.evidence import Evidence
from server.app.models.finding import Finding
from server.app.models.custody import ChainOfCustody
from server.app.models.event import InvestigationEvent
from server.app.core.benchmark_recorder import record_benchmark
from server.app.services.pcap_parser import parse_pcap_file, PcapAnalysisResult




def analyze_pcap_evidence(
    evidence: Evidence,
    db: Session,
    record_custody_event: bool = True,
) -> Dict[str, Any]:
    """
    Performs forensic inspection of a PCAP evidence artifact.

    Parameters:
      evidence: Evidence database model instance
      db: SQLAlchemy database session
      record_custody_event: Whether to log an ANALYZED event in chain-of-custody

    Returns:
      Dict with summary analysis and list of created Finding instances
    """
    evidence_path = Path(evidence.file_path)
    if not evidence_path.exists():
        raise FileNotFoundError(f"Evidence file not found on disk: {evidence.file_path}")

    # ------------------------------------------------------------------ #
    # Pre-analysis integrity guard                                         #
    # Recompute SHA-256 from disk and compare against the stored           #
    # acquisition hash. Abort if the file has been modified or corrupted.  #
    # ------------------------------------------------------------------ #
    pre_hasher = hashlib.sha256()
    with open(evidence_path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            pre_hasher.update(chunk)
    pre_analysis_hash = pre_hasher.hexdigest()

    if pre_analysis_hash.lower() != evidence.sha256_hash.lower():
        raise ValueError(
            f"Pre-analysis integrity check FAILED for '{evidence.evidence_id}'. "
            f"Stored acquisition hash: {evidence.sha256_hash}. "
            f"Current on-disk hash:    {pre_analysis_hash}. "
            "Analysis aborted — the artifact appears to have been modified after acquisition."
        )

    t_analysis_start = time.perf_counter()

    # Pure read-only parse
    parsed: PcapAnalysisResult = parse_pcap_file(evidence_path)

    findings_to_create: List[Finding] = []
    now_utc = datetime.now(timezone.utc)

    # Clean existing findings for this evidence to allow re-analysis idempotency
    db.query(Finding).filter(Finding.evidence_id == evidence.evidence_id).delete()

    if not parsed.is_valid_pcap:
        # Generate diagnostic / anomaly finding for non-standard or verification vector PCAP
        finding = Finding(
            finding_id=f"FND-{uuid.uuid4().hex[:12].upper()}",
            evidence_id=evidence.evidence_id,
            category="ANOMALY",
            severity="LOW",
            title=f"Non-Standard PCAP Header Detected in {evidence.file_name}",
            details=json.dumps({
                "file_name": evidence.file_name,
                "file_size": evidence.file_size_bytes,
                "sha256": evidence.sha256_hash,
                "warnings": parsed.parser_warnings,
                "note": "File acquired as PCAP artifact does not contain standard Libpcap magic signature.",
            }),
            detected_at=now_utc,
        )
        findings_to_create.append(finding)
    else:
        # Standard PCAP parsed successfully
        # 1. Baseline Ingestion Summary Finding
        summary_finding = Finding(
            finding_id=f"FND-{uuid.uuid4().hex[:12].upper()}",
            evidence_id=evidence.evidence_id,
            category="NETWORK_SUMMARY",
            severity="INFO",
            title=f"Network Capture Profile: {parsed.packet_count} packets across {len(parsed.protocols)} protocols",
            details=json.dumps({
                "packet_count": parsed.packet_count,
                "total_bytes": parsed.total_bytes,
                "duration_seconds": parsed.duration_seconds,
                "start_time": parsed.start_time.isoformat() if parsed.start_time else None,
                "end_time": parsed.end_time.isoformat() if parsed.end_time else None,
                "protocols": parsed.protocols,
                "unique_sources": len(parsed.source_ips),
                "unique_destinations": len(parsed.destination_ips),
            }),
            detected_at=now_utc,
        )
        findings_to_create.append(summary_finding)

        # 2. Port scan / Reconnaissance heuristic check
        # High count of distinct destination ports from a single source
        port_scan_threshold = 10
        src_dst_ports: Dict[str, Set[int]] = {}
        for pkt in parsed.raw_packets:
            if pkt.src_ip and pkt.dst_port:
                src_dst_ports.setdefault(pkt.src_ip, set()).add(pkt.dst_port)

        for src_ip, ports in src_dst_ports.items():
            if len(ports) >= port_scan_threshold:
                scan_finding = Finding(
                    finding_id=f"FND-{uuid.uuid4().hex[:12].upper()}",
                    evidence_id=evidence.evidence_id,
                    category="NETWORK_SCAN",
                    severity="HIGH",
                    title=f"Horizontal/Vertical Port Sweep Activity from {src_ip}",
                    details=json.dumps({
                        "source_ip": src_ip,
                        "unique_destination_ports": len(ports),
                        "probed_ports_sample": sorted(list(ports))[:20],
                    }),
                    detected_at=now_utc,
                )
                findings_to_create.append(scan_finding)

        # 3. Unencrypted Protocol Inspection (e.g. Telnet:23, HTTP:80)
        unencrypted_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3"}
        unencrypted_hits: Dict[str, List[int]] = {}
        for pkt in parsed.raw_packets:
            if pkt.dst_port in unencrypted_ports:
                proto_name = unencrypted_ports[pkt.dst_port]
                unencrypted_hits.setdefault(proto_name, []).append(pkt.dst_port)

        if unencrypted_hits:
            unenc_finding = Finding(
                finding_id=f"FND-{uuid.uuid4().hex[:12].upper()}",
                evidence_id=evidence.evidence_id,
                category="CLEAR_TEXT_TRAFFIC",
                severity="MEDIUM",
                title=f"Unencrypted Protocols Detected ({', '.join(unencrypted_hits.keys())})",
                details=json.dumps({
                    "protocols_found": {k: len(v) for k, v in unencrypted_hits.items()},
                    "recommendation": "Review payloads for cleartext credentials or sensitive tokens.",
                }),
                detected_at=now_utc,
            )
            findings_to_create.append(unenc_finding)

    # Save findings to database
    for f in findings_to_create:
        db.add(f)

    # Clean existing timeline events for this evidence to maintain idempotency
    db.query(InvestigationEvent).filter(InvestigationEvent.evidence_id == evidence.evidence_id).delete()

    # Generate chronological forensic events
    events_to_create: List[InvestigationEvent] = []

    # 1. Packet Flow Events (from parsed binary packets, up to 100 chronological network events)
    for pkt in parsed.raw_packets[:100]:
        pkt_dt = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc)
        proto_label = pkt.transport_proto or pkt.network_proto or "PACKET"
        endpoints_desc = ""
        if pkt.src_ip and pkt.dst_ip:
            endpoints_desc = f"{pkt.src_ip}:{pkt.src_port or 0} -> {pkt.dst_ip}:{pkt.dst_port or 0}"
        else:
            endpoints_desc = f"frame length {pkt.length}B"

        ev = InvestigationEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:12].upper()}",
            evidence_id=evidence.evidence_id,
            event_type="NETWORK_FLOW",
            source="pcap-dissector",
            severity="INFO",
            message=f"{proto_label} flow: {endpoints_desc}",
            metadata_json=json.dumps({
                "source_ip": pkt.src_ip,
                "destination_ip": pkt.dst_ip,
                "source_port": pkt.src_port,
                "destination_port": pkt.dst_port,
                "protocol": proto_label,
                "packet_length": pkt.length,
                "captured_length": pkt.captured_length,
                "tcp_flags": pkt.tcp_flags,
            }),
            timestamp=pkt_dt,
        )
        events_to_create.append(ev)

    # 2. Correlated Finding Events (from generated forensic findings)
    for f in findings_to_create:
        # Determine associated event severity
        evt_severity = f.severity if f.severity in ("INFO", "WARNING", "HIGH", "CRITICAL") else "WARNING"
        meta_dict = {}
        try:
            if f.details:
                meta_dict = json.loads(f.details)
        except Exception:
            meta_dict = {"details_raw": f.details}

        meta_dict["finding_id"] = f.finding_id
        meta_dict["finding_category"] = f.category

        ev = InvestigationEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:12].upper()}",
            evidence_id=evidence.evidence_id,
            event_type="SECURITY_FINDING",
            source="forensic-heuristics",
            severity=evt_severity,
            message=f"Threat Finding [{f.category}]: {f.title}",
            metadata_json=json.dumps(meta_dict),
            timestamp=f.detected_at,
        )
        events_to_create.append(ev)

    # Sort all events chronologically before adding to DB
    events_to_create.sort(key=lambda e: e.timestamp)

    for ev in events_to_create:
        db.add(ev)

    # Update evidence status to ANALYZED without mutating its hash
    evidence.status = "ANALYZED"

    # Optionally log chain-of-custody event
    if record_custody_event:
        custody_event = ChainOfCustody(
            evidence_id=evidence.evidence_id,
            action="ANALYZED",
            actor="forensight-pcap-engine",
            location=str(evidence_path),
            notes=(
                f"Automated forensic PCAP inspection completed. "
                f"Generated {len(findings_to_create)} findings and {len(events_to_create)} timeline events. "
                f"Pre-analysis integrity verified: stored SHA-256 ({evidence.sha256_hash}) "
                f"matched on-disk hash ({pre_analysis_hash})."
            ),
            timestamp=now_utc,
        )
        db.add(custody_event)

    db.commit()

    analysis_duration_sec = time.perf_counter() - t_analysis_start

    # Record genuine benchmark measurement for PCAP forensic analysis
    record_benchmark(
        db=db,
        benchmark_name="PCAP_ANALYSIS",
        duration_sec=analysis_duration_sec,
        sample_size_bytes=evidence.file_size_bytes,
        evidence_id=evidence.evidence_id,
        system_info=f"Packets: {parsed.packet_count}, Findings: {len(findings_to_create)}",
    )

    return {
        "evidence_id": evidence.evidence_id,
        "evidence_status": evidence.status,
        "is_valid_pcap": parsed.is_valid_pcap,
        "packet_count": parsed.packet_count,
        "total_bytes": parsed.total_bytes,
        "protocols": parsed.protocols,
        "source_ips": parsed.source_ips,
        "destination_ips": parsed.destination_ips,
        "source_ports": parsed.source_ports,
        "destination_ports": parsed.destination_ports,
        "conversations": parsed.conversations,
        "findings_count": len(findings_to_create),
        "findings": [
            {
                "finding_id": f.finding_id,
                "evidence_id": f.evidence_id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "details": f.details,
                "detected_at": f.detected_at.isoformat(),
            }
            for f in findings_to_create
        ],
    }
