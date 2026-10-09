"""
PCAP Parser & Forensic Network Inspection Engine
=================================================
Primary backend: PyShark (wraps tshark/Wireshark dissectors) for deep
application-layer inspection (DNS, HTTP, TLS, 1000+ protocols).

Fallback backend: Pure-Python struct/socket parser used when tshark is
not installed on the host (e.g. Windows dev machines, CI environments).

Both backends produce an identical PcapAnalysisResult so the upstream
pcap_analyzer.py and all API consumers require zero changes.

Design properties:
  - Non-destructive: read-only access to disk files in both backends.
  - Handles truncated packets safely without crashing.
  - Extracts packet count, timestamps, protocol distribution, IP endpoints,
    port endpoints, and conversations.
  - tshark detection is performed once at import time to avoid per-call
    overhead.

Backend selection:
  FORCE_PURE_PYTHON=1  (env var) – always use the fallback even if tshark
                                   is installed (useful for unit tests).
"""

import io
import json
import os
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Shared result dataclass (consumed by pcap_analyzer.py)
# ---------------------------------------------------------------------------

@dataclass
class PacketMetadata:
    timestamp: float
    length: int
    captured_length: int
    network_proto: Optional[str] = None   # IPv4, IPv6, ARP, etc.
    transport_proto: Optional[str] = None  # TCP, UDP, ICMP, etc.
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None


@dataclass
class PcapAnalysisResult:
    is_valid_pcap: bool
    packet_count: int = 0
    total_bytes: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)
    source_ips: Dict[str, int] = field(default_factory=dict)
    destination_ips: Dict[str, int] = field(default_factory=dict)
    source_ports: Dict[int, int] = field(default_factory=dict)
    destination_ports: Dict[int, int] = field(default_factory=dict)
    conversations: List[Dict[str, Any]] = field(default_factory=list)
    raw_packets: List[PacketMetadata] = field(default_factory=list)
    parser_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# tshark / PyShark availability detection
# ---------------------------------------------------------------------------

def _tshark_available() -> bool:
    """Return True when tshark is on PATH and executable."""
    if os.environ.get("FORCE_PURE_PYTHON", "").strip() == "1":
        return False
    return shutil.which("tshark") is not None


_TSHARK_PRESENT: bool = _tshark_available()


# ---------------------------------------------------------------------------
# PyShark backend
# ---------------------------------------------------------------------------

def _parse_with_pyshark(filepath: Path) -> PcapAnalysisResult:
    """
    Parse a PCAP/PCAPNG file using PyShark (tshark dissectors).

    Provides deep application-layer visibility: DNS, HTTP, TLS, 1000+
    protocols — far beyond what the pure-Python struct parser can decode.
    Returns a PcapAnalysisResult identical in shape to the fallback.
    """
    try:
        import pyshark  # noqa: PLC0415 — intentional deferred import
    except ImportError:
        result = PcapAnalysisResult(is_valid_pcap=False)
        result.parser_warnings.append(
            "pyshark is not installed. Install it with: pip install pyshark"
        )
        return result

    result = PcapAnalysisResult(is_valid_pcap=False)
    conversations_map: Dict[Tuple[str, str, str], int] = {}

    cap = None
    try:
        # Use default PDML/XML output (no use_json / use_ek).
        # use_json=True is DEPRECATED in PyShark 0.6 — TsharkJsonParser requires
        # a 'frame.protocols' key that is absent in many tshark JSON outputs,
        # causing a KeyError on every packet that is silently swallowed by the
        # per-packet exception handler, resulting in 0 packets parsed.
        cap = pyshark.FileCapture(
            str(filepath),
            keep_packets=False,  # stream packets; do not hold all in RAM
        )

        first_ts: Optional[float] = None
        last_ts: Optional[float] = None

        for pkt in cap:
            try:
                # ---- timestamp ----
                ts = float(pkt.sniff_timestamp)
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                # ---- sizes ----
                try:
                    frame_len = int(pkt.length)
                except AttributeError:
                    frame_len = 0

                captured_len = frame_len
                try:
                    captured_len = int(pkt.captured_length)
                except AttributeError:
                    pass

                result.packet_count += 1
                result.total_bytes += frame_len

                # ---- network / transport layers ----
                network_proto: Optional[str] = None
                transport_proto: Optional[str] = None
                src_ip: Optional[str] = None
                dst_ip: Optional[str] = None
                src_port: Optional[int] = None
                dst_port: Optional[int] = None
                tcp_flags_int: Optional[int] = None

                layers = [l.layer_name.upper() for l in pkt.layers]

                # Network layer
                if "IP" in layers:
                    network_proto = "IPv4"
                    try:
                        src_ip = pkt.ip.src
                        dst_ip = pkt.ip.dst
                    except AttributeError:
                        pass
                elif "IPV6" in layers:
                    network_proto = "IPv6"
                    try:
                        src_ip = pkt.ipv6.src
                        dst_ip = pkt.ipv6.dst
                    except AttributeError:
                        pass
                elif "ARP" in layers:
                    network_proto = "ARP"

                # Transport layer
                if "TCP" in layers:
                    transport_proto = "TCP"
                    try:
                        src_port = int(pkt.tcp.srcport)
                        dst_port = int(pkt.tcp.dstport)
                    except (AttributeError, ValueError):
                        pass
                    try:
                        tcp_flags_int = int(pkt.tcp.flags, 16)
                    except (AttributeError, ValueError):
                        pass
                elif "UDP" in layers:
                    transport_proto = "UDP"
                    try:
                        src_port = int(pkt.udp.srcport)
                        dst_port = int(pkt.udp.dstport)
                    except (AttributeError, ValueError):
                        pass
                elif "ICMP" in layers:
                    transport_proto = "ICMP"
                elif "ICMPV6" in layers:
                    transport_proto = "ICMPv6"

                # Application-layer enrichment: override proto label with
                # the highest recognised dissector when meaningful
                app_proto_candidates = [
                    l for l in layers
                    if l not in {
                        "ETH", "IP", "IPV6", "TCP", "UDP", "ARP",
                        "ICMP", "ICMPV6", "FRAME", "ETH_PADDING",
                        "WLAN", "RADIOTAP", "DATA", "DATA-TEXT-LINES",
                    }
                ]
                if app_proto_candidates:
                    # Use the outermost recognised application layer
                    transport_proto = transport_proto or app_proto_candidates[0]

                proto_key = transport_proto or network_proto or "OTHER"

                # ---- accumulate stats ----
                result.protocols[proto_key] = result.protocols.get(proto_key, 0) + 1

                if src_ip:
                    result.source_ips[src_ip] = result.source_ips.get(src_ip, 0) + 1
                if dst_ip:
                    result.destination_ips[dst_ip] = result.destination_ips.get(dst_ip, 0) + 1
                if src_port is not None:
                    result.source_ports[src_port] = result.source_ports.get(src_port, 0) + 1
                if dst_port is not None:
                    result.destination_ports[dst_port] = result.destination_ports.get(dst_port, 0) + 1
                if src_ip and dst_ip:
                    conv_key = (src_ip, dst_ip, proto_key)
                    conversations_map[conv_key] = conversations_map.get(conv_key, 0) + 1

                # ---- store packet metadata for analyzer heuristics ----
                result.raw_packets.append(PacketMetadata(
                    timestamp=ts,
                    length=frame_len,
                    captured_length=captured_len,
                    network_proto=network_proto,
                    transport_proto=transport_proto,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_flags=tcp_flags_int,
                ))

            except Exception as pkt_exc:
                result.parser_warnings.append(f"Skipped malformed packet: {pkt_exc}")
                continue

        # ---- mark valid if tshark processed the file without an outer error ----
        result.is_valid_pcap = True

        # ---- timestamps / duration ----
        if first_ts is not None:
            result.start_time = datetime.fromtimestamp(first_ts, tz=timezone.utc)
        if last_ts is not None:
            result.end_time = datetime.fromtimestamp(last_ts, tz=timezone.utc)
        if first_ts is not None and last_ts is not None:
            result.duration_seconds = round(max(0.0, last_ts - first_ts), 4)

        # ---- top-50 conversations ----
        for (src, dst, proto), count in sorted(
            conversations_map.items(), key=lambda x: x[1], reverse=True
        )[:50]:
            result.conversations.append({
                "source_ip": src,
                "destination_ip": dst,
                "protocol": proto,
                "packet_count": count,
            })

    finally:
        # Always close the capture to terminate the tshark subprocess.
        if cap is not None:
            try:
                cap.close()
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# Pure-Python fallback backend (no external dependencies)
# ---------------------------------------------------------------------------

# Global PCAP magic numbers
_PCAP_MAGIC_MICRO_LE = 0xD4C3B2A1
_PCAP_MAGIC_MICRO_BE = 0xA1B2C3D4
_PCAP_MAGIC_NANO_LE  = 0x4D3CB2A1
_PCAP_MAGIC_NANO_BE  = 0xA1B23C4D

# Link layer types (Data Link Types)
_DLT_NULL      = 0
_DLT_EN10MB    = 1    # Ethernet
_DLT_RAW       = 12   # Raw IP
_DLT_LOOP      = 108  # OpenBSD loopback
_DLT_LINUX_SLL = 113  # Linux cooked capture


def _parse_ipv4(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str], bytes]:
    """Parse IPv4 packet header."""
    if len(payload) < 20:
        return None, None, None, b""
    ihl = (payload[0] & 0x0F) * 4
    if len(payload) < ihl:
        return None, None, None, b""
    protocol_num = payload[9]
    src_ip = socket.inet_ntoa(payload[12:16])
    dst_ip = socket.inet_ntoa(payload[16:20])
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
    transport_proto = proto_map.get(protocol_num, f"IP-{protocol_num}")
    return src_ip, dst_ip, transport_proto, payload[ihl:]


def _parse_ipv6(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str], bytes]:
    """Parse IPv6 packet header."""
    if len(payload) < 40:
        return None, None, None, b""
    next_header = payload[6]
    src_ip = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
    transport_proto = proto_map.get(next_header, f"IPv6-{next_header}")
    return src_ip, dst_ip, transport_proto, payload[40:]


def _parse_transport(proto: str, payload: bytes) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Extract ports and flags from transport layer payload."""
    src_port = None
    dst_port = None
    tcp_flags = None

    if proto == "TCP" and len(payload) >= 14:
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        tcp_flags = payload[13]
    elif proto == "UDP" and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[0:4])

    return src_port, dst_port, tcp_flags


def _parse_with_pure_python(raw_bytes: bytes) -> PcapAnalysisResult:
    """
    Pure-Python PCAP parser (no external C-library dependency).
    Used as fallback when tshark is not available.
    Handles standard Libpcap PCAP files (microsecond and nanosecond timestamps,
    big-endian and little-endian byte orders).
    """
    result = PcapAnalysisResult(is_valid_pcap=False)

    if len(raw_bytes) < 24:
        result.parser_warnings.append(
            f"Payload too short for PCAP global header ({len(raw_bytes)} bytes)."
        )
        return result

    magic = struct.unpack(">I", raw_bytes[:4])[0]
    endian = ""
    is_nano = False

    if magic == _PCAP_MAGIC_MICRO_BE:
        endian = ">"
        is_nano = False
    elif struct.unpack("<I", raw_bytes[:4])[0] == 0xA1B2C3D4:
        endian = "<"
        is_nano = False
    elif magic == _PCAP_MAGIC_NANO_BE:
        endian = ">"
        is_nano = True
    elif struct.unpack("<I", raw_bytes[:4])[0] == 0xA1B23C4D:
        endian = "<"
        is_nano = True
    else:
        result.parser_warnings.append("Magic number does not match standard PCAP format.")
        return result

    result.is_valid_pcap = True

    try:
        _, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack(
            f"{endian}IHHiIII", raw_bytes[:24]
        )
    except struct.error as exc:
        result.parser_warnings.append(f"Corrupt global header: {exc}")
        return result

    offset = 24
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    conversations_map: Dict[Tuple[str, str, str], int] = {}

    while offset + 16 <= len(raw_bytes):
        try:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{endian}IIII", raw_bytes[offset: offset + 16]
            )
        except struct.error:
            break

        offset += 16
        packet_payload = raw_bytes[offset: offset + incl_len]
        offset += incl_len

        ts_divisor = 1_000_000_000.0 if is_nano else 1_000_000.0
        ts = float(ts_sec) + (float(ts_usec) / ts_divisor)

        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts

        result.packet_count += 1
        result.total_bytes += orig_len

        packet = PacketMetadata(
            timestamp=ts,
            length=orig_len,
            captured_length=incl_len,
        )

        # Parse Link Layer
        network_payload = b""
        if network == _DLT_EN10MB and len(packet_payload) >= 14:
            eth_type = struct.unpack("!H", packet_payload[12:14])[0]
            network_payload = packet_payload[14:]
            if eth_type == 0x0800:
                packet.network_proto = "IPv4"
            elif eth_type == 0x86DD:
                packet.network_proto = "IPv6"
            elif eth_type == 0x0806:
                packet.network_proto = "ARP"
            else:
                packet.network_proto = f"0x{eth_type:04x}"
        elif network == _DLT_RAW:
            packet.network_proto = "IPv4" if (
                packet_payload and (packet_payload[0] >> 4) == 4
            ) else "IPv6"
            network_payload = packet_payload
        else:
            network_payload = packet_payload

        # Parse Network Layer
        transport_payload = b""
        if packet.network_proto == "IPv4":
            s_ip, d_ip, trans_proto, transport_payload = _parse_ipv4(network_payload)
            packet.src_ip = s_ip
            packet.dst_ip = d_ip
            packet.transport_proto = trans_proto
        elif packet.network_proto == "IPv6":
            s_ip, d_ip, trans_proto, transport_payload = _parse_ipv6(network_payload)
            packet.src_ip = s_ip
            packet.dst_ip = d_ip
            packet.transport_proto = trans_proto

        # Parse Transport Layer
        if packet.transport_proto:
            sp, dp, flags = _parse_transport(packet.transport_proto, transport_payload)
            packet.src_port = sp
            packet.dst_port = dp
            packet.tcp_flags = flags

            if sp is not None:
                result.source_ports[sp] = result.source_ports.get(sp, 0) + 1
            if dp is not None:
                result.destination_ports[dp] = result.destination_ports.get(dp, 0) + 1

        proto_key = packet.transport_proto or packet.network_proto or "OTHER"
        result.protocols[proto_key] = result.protocols.get(proto_key, 0) + 1

        if packet.src_ip:
            result.source_ips[packet.src_ip] = result.source_ips.get(packet.src_ip, 0) + 1
        if packet.dst_ip:
            result.destination_ips[packet.dst_ip] = result.destination_ips.get(packet.dst_ip, 0) + 1
        if packet.src_ip and packet.dst_ip:
            conv_key = (packet.src_ip, packet.dst_ip, proto_key)
            conversations_map[conv_key] = conversations_map.get(conv_key, 0) + 1

        result.raw_packets.append(packet)

    if first_ts is not None:
        result.start_time = datetime.fromtimestamp(first_ts, tz=timezone.utc)
    if last_ts is not None:
        result.end_time = datetime.fromtimestamp(last_ts, tz=timezone.utc)
    if first_ts is not None and last_ts is not None:
        result.duration_seconds = round(max(0.0, last_ts - first_ts), 4)

    for (src, dst, proto), count in sorted(
        conversations_map.items(), key=lambda x: x[1], reverse=True
    )[:50]:
        result.conversations.append({
            "source_ip": src,
            "destination_ip": dst,
            "protocol": proto,
            "packet_count": count,
        })

    return result


# ---------------------------------------------------------------------------
# Public API (consumed by pcap_analyzer.py)
# ---------------------------------------------------------------------------

def parse_pcap_bytes(raw_bytes: bytes) -> PcapAnalysisResult:
    """
    Parse PCAP data from raw bytes.

    Uses PyShark (tshark) when available; falls back to the pure-Python
    parser otherwise.  Writes to a temporary file for PyShark since it
    requires a filesystem path.
    """
    if _TSHARK_PRESENT:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(raw_bytes)
            tmp_path = Path(tmp.name)
        try:
            return _parse_with_pyshark(tmp_path)
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass
    else:
        return _parse_with_pure_python(raw_bytes)


def parse_pcap_file(filepath: Path) -> PcapAnalysisResult:
    """
    Parse a PCAP file from disk.

    Uses PyShark (tshark) when available; falls back to pure-Python
    struct-based parsing otherwise.  The file is opened read-only in
    both backends.
    """
    if _TSHARK_PRESENT:
        return _parse_with_pyshark(filepath)
    else:
        with open(filepath, "rb") as f:
            data = f.read()
        return _parse_with_pure_python(data)


def backend_info() -> Dict[str, Any]:
    """
    Returns information about the active parsing backend.
    Useful for health checks and dashboard status cards.
    """
    if _TSHARK_PRESENT:
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version_line = result.stdout.splitlines()[0] if result.stdout else "unknown"
        except Exception:
            version_line = "tshark present but version query failed"
        return {
            "backend": "pyshark",
            "tshark_available": True,
            "tshark_version": version_line,
            "capabilities": [
                "deep_packet_inspection",
                "application_layer_dissection",
                "dns_analysis",
                "http_inspection",
                "tls_metadata",
                "1000+ protocols",
            ],
        }
    else:
        return {
            "backend": "pure_python",
            "tshark_available": False,
            "tshark_version": None,
            "capabilities": [
                "ethernet_layer2",
                "ipv4_ipv6",
                "tcp_udp_icmp",
                "port_scan_heuristics",
                "cleartext_protocol_detection",
            ],
        }
