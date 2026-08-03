"""
Generate dashboard data from a pcap file.

The generated JavaScript file can be opened by network_dashboard.html without
requiring a local web server.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import importlib.util
import json
import pathlib
import struct
import sys
from typing import Any, Optional


BASE_DIR = pathlib.Path(__file__).resolve().parent
PACKET_CAPTURE_PATH = BASE_DIR / "packet_capture.py"


def load_packet_capture_module():
    spec = importlib.util.spec_from_file_location("packet_capture", PACKET_CAPTURE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PACKET_CAPTURE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CAPTURE = load_packet_capture_module()


PORT_SERVICES = {
    20: "FTP data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP submit",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alt",
    8443: "HTTPS alt",
}


def parse_pcap(path: pathlib.Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path} is too small to be a pcap file")

    magic_bytes = data[:4]
    if magic_bytes == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        scale = 1_000_000
    elif magic_bytes == b"\xa1\xb2\xc3\xd4":
        endian = ">"
        scale = 1_000_000
    elif magic_bytes == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        scale = 1_000_000_000
    elif magic_bytes == b"\xa1\xb2\x3c\x4d":
        endian = ">"
        scale = 1_000_000_000
    else:
        raise ValueError(f"{path} does not start with a supported pcap magic number")

    _magic, version_major, version_minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
        f"{endian}IHHIIII", data[:24]
    )
    metadata = {
        "path": str(path),
        "fileName": path.name,
        "fileSize": len(data),
        "version": f"{version_major}.{version_minor}",
        "thiszone": thiszone,
        "sigfigs": sigfigs,
        "snaplen": snaplen,
        "linktype": linktype,
        "timestampResolution": "nanoseconds" if scale == 1_000_000_000 else "microseconds",
    }

    packets: list[dict[str, Any]] = []
    offset = 24
    packet_index = 1

    while offset + 16 <= len(data):
        ts_sec, ts_frac, included_len, original_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        if offset + included_len > len(data):
            raise ValueError(f"pcap packet {packet_index} extends past the end of the file")

        payload = data[offset : offset + included_len]
        offset += included_len
        timestamp = ts_sec + (ts_frac / scale)
        summary = CAPTURE.decode_packet(payload, timestamp=timestamp, linktype=linktype)

        src_endpoint = format_endpoint(summary.src, summary.src_port)
        dst_endpoint = format_endpoint(summary.dst, summary.dst_port)
        service = guess_service(summary.src_port, summary.dst_port, summary.transport)

        packets.append(
            {
                "index": packet_index,
                "timestamp": timestamp,
                "time": dt.datetime.fromtimestamp(timestamp).isoformat(timespec="milliseconds"),
                "length": summary.length,
                "includedLength": included_len,
                "originalLength": original_len,
                "layer2": summary.layer2,
                "network": summary.network,
                "transport": summary.transport,
                "protocol": summary.protocol_text(),
                "src": summary.src,
                "dst": summary.dst,
                "srcPort": summary.src_port,
                "dstPort": summary.dst_port,
                "srcEndpoint": src_endpoint,
                "dstEndpoint": dst_endpoint,
                "service": service,
                "info": summary.info,
                "hexPreview": payload[:32].hex(" "),
            }
        )
        packet_index += 1

    if offset != len(data):
        metadata["trailingBytes"] = len(data) - offset

    return metadata, packets


def format_endpoint(host: str, port: Optional[int]) -> str:
    if port is None:
        return host
    return f"{host}:{port}"


def guess_service(src_port: Optional[int], dst_port: Optional[int], transport: str) -> str:
    for port in (dst_port, src_port):
        if port in PORT_SERVICES:
            return PORT_SERVICES[port]
    if transport and transport != "-":
        return transport
    return "Other"


def summarize(metadata: dict[str, Any], packets: list[dict[str, Any]]) -> dict[str, Any]:
    total_packets = len(packets)
    total_bytes = sum(packet["length"] for packet in packets)
    first_ts = packets[0]["timestamp"] if packets else None
    last_ts = packets[-1]["timestamp"] if packets else None
    duration = max(0.0, (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0)

    protocol_counts: collections.Counter[str] = collections.Counter()
    protocol_bytes: collections.Counter[str] = collections.Counter()
    service_counts: collections.Counter[str] = collections.Counter()
    endpoint_counts: collections.Counter[str] = collections.Counter()
    endpoint_bytes: collections.Counter[str] = collections.Counter()
    conversation_counts: collections.Counter[str] = collections.Counter()
    conversation_bytes: collections.Counter[str] = collections.Counter()
    timeline: collections.defaultdict[str, dict[str, Any]] = collections.defaultdict(lambda: {"packets": 0, "bytes": 0})

    for packet in packets:
        protocol = packet["transport"] if packet["transport"] and packet["transport"] != "-" else packet["network"]
        protocol_counts[protocol] += 1
        protocol_bytes[protocol] += packet["length"]
        service_counts[packet["service"]] += 1

        for endpoint in (packet["srcEndpoint"], packet["dstEndpoint"]):
            endpoint_counts[endpoint] += 1
            endpoint_bytes[endpoint] += packet["length"]

        pair = canonical_conversation(packet["srcEndpoint"], packet["dstEndpoint"])
        conversation_counts[pair] += 1
        conversation_bytes[pair] += packet["length"]

        bucket = dt.datetime.fromtimestamp(packet["timestamp"]).strftime("%H:%M:%S")
        timeline[bucket]["packets"] += 1
        timeline[bucket]["bytes"] += packet["length"]

    insights = build_insights(metadata, packets, protocol_counts, service_counts, duration)

    return {
        "totalPackets": total_packets,
        "totalBytes": total_bytes,
        "durationSeconds": round(duration, 3),
        "startTime": dt.datetime.fromtimestamp(first_ts).isoformat(timespec="seconds") if first_ts else None,
        "endTime": dt.datetime.fromtimestamp(last_ts).isoformat(timespec="seconds") if last_ts else None,
        "packetsPerSecond": round(total_packets / duration, 2) if duration > 0 else total_packets,
        "bytesPerSecond": round(total_bytes / duration, 2) if duration > 0 else total_bytes,
        "protocols": top_items(protocol_counts, protocol_bytes, limit=12),
        "services": top_simple_items(service_counts, limit=12),
        "topEndpoints": top_items(endpoint_counts, endpoint_bytes, limit=12),
        "topConversations": top_items(conversation_counts, conversation_bytes, limit=12),
        "timeline": [{"time": key, **value} for key, value in sorted(timeline.items())],
        "insights": insights,
    }


def canonical_conversation(left: str, right: str) -> str:
    return " <-> ".join(sorted((left, right)))


def top_items(
    counts: collections.Counter[str],
    bytes_counter: collections.Counter[str],
    limit: int,
) -> list[dict[str, Any]]:
    rows = []
    for name, count in counts.most_common(limit):
        rows.append({"name": name, "count": count, "bytes": bytes_counter[name]})
    return rows


def top_simple_items(counts: collections.Counter[str], limit: int) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in counts.most_common(limit)]


def build_insights(
    metadata: dict[str, Any],
    packets: list[dict[str, Any]],
    protocol_counts: collections.Counter[str],
    service_counts: collections.Counter[str],
    duration: float,
) -> list[dict[str, str]]:
    insights: list[dict[str, str]] = []

    if not packets:
        insights.append(
            {
                "level": "notice",
                "title": "No packets captured",
                "body": "The pcap contains only a header. Run a longer capture or generate traffic while capture is active.",
            }
        )
        return insights

    if metadata.get("linktype") == 101:
        insights.append(
            {
                "level": "notice",
                "title": "Layer-3 capture",
                "body": "This pcap stores raw IP packets, so Ethernet MAC addresses and ARP traffic are not available.",
            }
        )

    top_protocol, top_protocol_count = protocol_counts.most_common(1)[0]
    if top_protocol_count == len(packets):
        insights.append(
            {
                "level": "info",
                "title": f"All packets are {top_protocol}",
                "body": f"The sample is narrowly focused: {top_protocol_count} of {len(packets)} packets use {top_protocol}.",
            }
        )

    if service_counts.get("DNS", 0):
        insights.append(
            {
                "level": "info",
                "title": "DNS activity detected",
                "body": f"{service_counts['DNS']} packet(s) use port 53, which usually means name-resolution traffic.",
            }
        )

    if duration < 10 and len(packets) < 20:
        insights.append(
            {
                "level": "notice",
                "title": "Short capture window",
                "body": "Capture for 30-60 seconds to see a more representative traffic mix.",
            }
        )

    return insights


def build_payload(pcap_path: pathlib.Path, metadata: dict[str, Any], packets: list[dict[str, Any]]) -> dict[str, Any]:
    generated_at = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    return {
        "generatedAt": generated_at,
        "source": {
            "name": pcap_path.name,
            "path": str(pcap_path),
        },
        "metadata": metadata,
        "summary": summarize(metadata, packets),
        "packets": packets,
    }


def write_dashboard_data(payload: dict[str, Any], out_path: pathlib.Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(payload, indent=2, sort_keys=False)
    out_path.write_text(
        "window.NETWORK_DASHBOARD_DATA = " + json_text + ";\n",
        encoding="utf-8",
    )


def positive_path(value: str) -> pathlib.Path:
    return pathlib.Path(value).expanduser().resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate dashboard_data.js from a packet capture file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        type=positive_path,
        default=BASE_DIR / "live_capture_admin.pcap",
        help="pcap file to analyze",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=positive_path,
        default=BASE_DIR / "dashboard_data.js",
        help="dashboard JavaScript output file",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    metadata, packets = parse_pcap(args.pcap)
    payload = build_payload(args.pcap, metadata, packets)
    write_dashboard_data(payload, args.output)

    total_packets = payload["summary"]["totalPackets"]
    total_bytes = payload["summary"]["totalBytes"]
    duration = payload["summary"]["durationSeconds"]
    print(f"wrote {args.output}")
    print(f"packets={total_packets} bytes={total_bytes} duration={duration}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
