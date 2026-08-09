#!/usr/bin/env python3
"""
ids_engine.py – Network Intrusion Detection System (NIDS)

Detection rules
---------------
1.  Port scan          – one source IP hits N distinct dst-ports in a short window
2.  SYN flood          – one source IP sends M SYN packets in a short window
3.  ICMP flood         – one source IP sends K ICMP packets in a short window
4.  Brute-force login  – many TCP packets to a single auth port (SSH/RDP/FTP/Telnet)
5.  ARP spoofing       – same IP claimed by more than one MAC
6.  DNS tunneling      – single source sends many DNS queries in a short window
7.  Suspicious ports   – traffic on well-known dangerous ports (Telnet 23, NetBIOS …)

Output
------
  • Terminal  – coloured ALERT lines printed in real-time
  • Log file  – plain-text log (ids_alerts.log by default)
  • Dashboard – ids_threats.js written after analysis; loaded by network_dashboard.html

Usage examples
--------------
  # Analyse an existing pcap
  python ids_engine.py live_capture_admin.pcap

  # Live capture for 60 s then analyse
  python ids_engine.py --live --duration 60 --output capture.pcap

  # Live capture + write custom alert log
  python ids_engine.py --live --duration 30 --alert-log threats.log

Response mechanisms
-------------------
  --block-firewall   Add Windows Firewall rules to block attacker IPs (requires Admin)
  --block-hosts      Append attacker IPs to a hosts-file block list
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import importlib.util
import json
import os
import pathlib
import platform
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Load sibling packet_capture module
_BASE = pathlib.Path(__file__).resolve().parent


def _load_capture_module(path: pathlib.Path):
    if not path.exists():
        raise FileNotFoundError(
            f"Cannot find {path}. "
            "Place ids_engine.py in the same folder as packet_capture.py."
        )
    spec = importlib.util.spec_from_file_location("packet_capture", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[spec.name] = mod  # type: ignore[index]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


CAPTURE = _load_capture_module(_BASE / "packet_capture.py")

# ---------------------------------------------------------------------------
# Severity colours (ANSI)
# ---------------------------------------------------------------------------
_ANSI = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH":     "\033[0;31m",  # red
    "MEDIUM":   "\033[0;33m",  # yellow
    "LOW":      "\033[0;36m",  # cyan
    "RESET":    "\033[0m",
}

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")


def _color(severity: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"{_ANSI.get(severity, '')}{text}{_ANSI['RESET']}"


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    timestamp: float
    rule: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    src_ip: str
    dst_ip: str
    detail: str
    packet_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "time": dt.datetime.fromtimestamp(self.timestamp).isoformat(timespec="milliseconds"),
            "rule": self.rule,
            "severity": self.severity,
            "srcIp": self.src_ip,
            "dstIp": self.dst_ip,
            "detail": self.detail,
            "packetIndices": self.packet_indices,
        }

    def format_line(self) -> str:
        ts = dt.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]
        line = (
            f"[{ts}] [{self.severity:<8}] {self.rule:<22} "
            f"{self.src_ip} -> {self.dst_ip}  |  {self.detail}"
        )
        return _color(self.severity, line)


# ---------------------------------------------------------------------------
# Thresholds (tuneable via CLI)
# ---------------------------------------------------------------------------
@dataclass
class Thresholds:
    portscan_ports: int = 15       # distinct dst-ports in window → port scan
    portscan_window: float = 5.0   # seconds
    synflood_count: int = 30       # SYN packets in window → SYN flood
    synflood_window: float = 3.0
    icmpflood_count: int = 20      # ICMP packets in window → ICMP flood
    icmpflood_window: float = 3.0
    bruteforce_count: int = 10     # TCP packets to single auth port
    bruteforce_window: float = 5.0
    dnstunnel_count: int = 15      # DNS queries in window → tunneling suspicion
    dnstunnel_window: float = 5.0


# ---------------------------------------------------------------------------
# Suspicious ports
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS: dict[int, str] = {
    23:   "Telnet (cleartext credential risk)",
    135:  "MS-RPC (often exploited)",
    137:  "NetBIOS Name Service",
    139:  "NetBIOS Session Service",
    445:  "SMB (ransomware target)",
    1433: "MSSQL",
    1521: "Oracle DB",
    3389: "RDP (brute-force target)",
    4444: "Metasploit default shell",
    5900: "VNC (remote desktop)",
    6379: "Redis (often unauthenticated)",
    8080: "HTTP alt (potential proxy abuse)",
    9200: "Elasticsearch (often unauthenticated)",
}

AUTH_PORTS: set[int] = {21, 22, 23, 25, 110, 143, 3389, 5900}

# ---------------------------------------------------------------------------
# IDS Engine
# ---------------------------------------------------------------------------


class IDSEngine:
    def __init__(
        self,
        thresholds: Thresholds,
        alert_log: Optional[pathlib.Path] = None,
        block_firewall: bool = False,
        block_hosts: Optional[pathlib.Path] = None,
        quiet: bool = False,
    ) -> None:
        self.thresholds = thresholds
        self.alert_log = alert_log
        self.block_firewall = block_firewall
        self.block_hosts = block_hosts
        self.quiet = quiet

        self.alerts: list[Alert] = []
        self._blocked_ips: set[str] = set()
        self._log_fh = open(alert_log, "a", encoding="utf-8") if alert_log else None

        # Per-source sliding-window state
        # { src_ip: deque of (timestamp, extra) }
        self._syn_times: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._icmp_times: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._dns_times: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # { src_ip: { dst_port: [timestamps] } }
        self._scan_ports: dict[str, dict[int, list[float]]] = collections.defaultdict(
            lambda: collections.defaultdict(list)
        )
        # { src_ip: deque of timestamps } per auth port
        self._brute_times: dict[str, dict[int, collections.deque]] = collections.defaultdict(
            lambda: collections.defaultdict(collections.deque)
        )
        # ARP table: { sender_ip: set of MACs }
        self._arp_table: dict[str, set[str]] = collections.defaultdict(set)
        # Already-fired keys to avoid alert storms
        self._fired: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, pkt: dict[str, Any]) -> list[Alert]:
        """Inspect one decoded packet dict (as produced by generate_dashboard.py)."""
        new_alerts: list[Alert] = []
        ts = float(pkt["timestamp"])
        src = pkt.get("src", "-")
        dst = pkt.get("dst", "-")
        transport = pkt.get("transport", "-")
        src_port = pkt.get("srcPort")
        dst_port = pkt.get("dstPort")
        info = pkt.get("info", "")
        index = pkt.get("index", 0)
        layer2 = pkt.get("layer2", "-")

        # --- Rule 1: Port scan ---
        if transport in ("TCP", "UDP") and dst_port is not None:
            self._scan_ports[src][dst_port].append(ts)
            self._evict_old(self._scan_ports[src][dst_port], ts, self.thresholds.portscan_window)
            distinct_ports = sum(
                1 for times in self._scan_ports[src].values()
                if any(t > ts - self.thresholds.portscan_window for t in times)
            )
            key = f"portscan:{src}"
            if distinct_ports >= self.thresholds.portscan_ports and key not in self._fired:
                self._fired.add(key)
                a = Alert(
                    timestamp=ts, rule="Port Scan", severity="HIGH",
                    src_ip=src, dst_ip=dst,
                    detail=f"{distinct_ports} distinct dst-ports in {self.thresholds.portscan_window}s",
                    packet_indices=[index],
                )
                new_alerts.append(a)

        # --- Rule 2: SYN flood ---
        if transport == "TCP" and "SYN" in info and "ACK" not in info:
            dq = self._syn_times[src]
            dq.append(ts)
            self._evict_dq(dq, ts, self.thresholds.synflood_window)
            key = f"synflood:{src}"
            if len(dq) >= self.thresholds.synflood_count and key not in self._fired:
                self._fired.add(key)
                a = Alert(
                    timestamp=ts, rule="SYN Flood", severity="CRITICAL",
                    src_ip=src, dst_ip=dst,
                    detail=f"{len(dq)} SYN packets in {self.thresholds.synflood_window}s",
                    packet_indices=[index],
                )
                new_alerts.append(a)

        # --- Rule 3: ICMP flood ---
        if transport in ("ICMP", "ICMPv6"):
            dq = self._icmp_times[src]
            dq.append(ts)
            self._evict_dq(dq, ts, self.thresholds.icmpflood_window)
            key = f"icmpflood:{src}"
            if len(dq) >= self.thresholds.icmpflood_count and key not in self._fired:
                self._fired.add(key)
                a = Alert(
                    timestamp=ts, rule="ICMP Flood", severity="HIGH",
                    src_ip=src, dst_ip=dst,
                    detail=f"{len(dq)} ICMP packets in {self.thresholds.icmpflood_window}s",
                    packet_indices=[index],
                )
                new_alerts.append(a)

        # --- Rule 4: Brute-force login ---
        if transport == "TCP" and dst_port in AUTH_PORTS:
            dq = self._brute_times[src][dst_port]
            dq.append(ts)
            self._evict_dq(dq, ts, self.thresholds.bruteforce_window)
            key = f"brute:{src}:{dst_port}"
            if len(dq) >= self.thresholds.bruteforce_count and key not in self._fired:
                self._fired.add(key)
                a = Alert(
                    timestamp=ts, rule="Brute-Force Login", severity="HIGH",
                    src_ip=src, dst_ip=dst,
                    detail=f"{len(dq)} TCP packets to port {dst_port} in {self.thresholds.bruteforce_window}s",
                    packet_indices=[index],
                )
                new_alerts.append(a)

        # --- Rule 5: ARP spoofing ---
        if pkt.get("network") == "ARP" and "is-at" in info:
            # info = "is-at <sender_ip>"  and src = sender_mac from ARP decode
            # We rely on packet_capture's ARP decode: src=sender_mac, info="is-at <sender_ip>"
            claimed_ip = info.replace("is-at", "").strip()
            if claimed_ip and src != "-":
                self._arp_table[claimed_ip].add(src)
                if len(self._arp_table[claimed_ip]) > 1:
                    macs = ", ".join(self._arp_table[claimed_ip])
                    key = f"arpspoofing:{claimed_ip}"
                    if key not in self._fired:
                        self._fired.add(key)
                        a = Alert(
                            timestamp=ts, rule="ARP Spoofing", severity="CRITICAL",
                            src_ip=src, dst_ip=dst,
                            detail=f"IP {claimed_ip} claimed by multiple MACs: {macs}",
                            packet_indices=[index],
                        )
                        new_alerts.append(a)

        # --- Rule 6: DNS tunneling ---
        if dst_port == 53 or src_port == 53:
            dq = self._dns_times[src]
            dq.append(ts)
            self._evict_dq(dq, ts, self.thresholds.dnstunnel_window)
            key = f"dnstunnel:{src}"
            if len(dq) >= self.thresholds.dnstunnel_count and key not in self._fired:
                self._fired.add(key)
                a = Alert(
                    timestamp=ts, rule="DNS Tunneling", severity="MEDIUM",
                    src_ip=src, dst_ip=dst,
                    detail=f"{len(dq)} DNS packets in {self.thresholds.dnstunnel_window}s (possible data exfil)",
                    packet_indices=[index],
                )
                new_alerts.append(a)

        # --- Rule 7: Suspicious port ---
        for port in (src_port, dst_port):
            if port in SUSPICIOUS_PORTS:
                key = f"suspport:{src}:{dst}:{port}"
                if key not in self._fired:
                    self._fired.add(key)
                    a = Alert(
                        timestamp=ts, rule="Suspicious Port", severity="MEDIUM",
                        src_ip=src, dst_ip=dst,
                        detail=f"Port {port} – {SUSPICIOUS_PORTS[port]}",
                        packet_indices=[index],
                    )
                    new_alerts.append(a)

        for alert in new_alerts:
            self._emit(alert)

        return new_alerts

    def close(self) -> None:
        if self._log_fh:
            self._log_fh.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit(self, alert: Alert) -> None:
        self.alerts.append(alert)
        line = alert.format_line()
        if not self.quiet:
            print(line)
        if self._log_fh:
            self._log_fh.write(line.replace("\033[1;31m", "").replace("\033[0;31m", "")
                               .replace("\033[0;33m", "").replace("\033[0;36m", "")
                               .replace("\033[0m", "") + "\n")
            self._log_fh.flush()
        if self.block_firewall and alert.src_ip not in self._blocked_ips:
            self._block_via_firewall(alert.src_ip)
        if self.block_hosts and alert.src_ip not in self._blocked_ips:
            self._block_via_hosts(alert.src_ip)

    @staticmethod
    def _evict_old(lst: list, now: float, window: float) -> None:
        cutoff = now - window
        while lst and lst[0] < cutoff:
            lst.pop(0)

    @staticmethod
    def _evict_dq(dq: collections.deque, now: float, window: float) -> None:
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _block_via_firewall(self, ip: str) -> None:
        self._blocked_ips.add(ip)
        if platform.system().lower() != "windows":
            print(f"  [RESPONSE] Firewall block is Windows-only; skipping {ip}", file=sys.stderr)
            return
        rule_name = f"IDS-Block-{ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(_color("CRITICAL", f"  [RESPONSE] Blocked {ip} via Windows Firewall (rule: {rule_name})"))
        except subprocess.CalledProcessError as exc:
            print(f"  [RESPONSE] Firewall block failed for {ip}: {exc.stderr.decode()}", file=sys.stderr)

    def _block_via_hosts(self, ip: str) -> None:
        self._blocked_ips.add(ip)
        try:
            with open(self.block_hosts, "a", encoding="utf-8") as fh:
                fh.write(f"0.0.0.0 {ip}  # IDS block {dt.datetime.now().isoformat()}\n")
            print(_color("HIGH", f"  [RESPONSE] Added {ip} to hosts block list ({self.block_hosts})"))
        except OSError as exc:
            print(f"  [RESPONSE] Hosts file write failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# PCAP analysis
# ---------------------------------------------------------------------------


def read_pcap_packets(path: pathlib.Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a pcap and return (metadata, list_of_packet_dicts)."""
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path} is too small to be a pcap")

    magic = data[:4]
    endian_scale = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in endian_scale:
        raise ValueError(f"{path}: unsupported pcap magic")
    endian, scale = endian_scale[magic]

    _, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(f"{endian}IHHIIII", data[:24])
    metadata: dict[str, Any] = {
        "path": str(path), "fileName": path.name, "fileSize": len(data),
        "version": f"{ver_maj}.{ver_min}", "snaplen": snaplen, "linktype": linktype,
    }

    packets: list[dict[str, Any]] = []
    offset = 24
    idx = 1
    while offset + 16 <= len(data):
        ts_sec, ts_frac, inc_len, orig_len = struct.unpack(f"{endian}IIII", data[offset:offset + 16])
        offset += 16
        if offset + inc_len > len(data):
            break
        payload = data[offset:offset + inc_len]
        offset += inc_len
        ts = ts_sec + ts_frac / scale
        s = CAPTURE.decode_packet(payload, timestamp=ts, linktype=linktype)
        packets.append({
            "index": idx,
            "timestamp": ts,
            "time": dt.datetime.fromtimestamp(ts).isoformat(timespec="milliseconds"),
            "length": s.length,
            "layer2": s.layer2,
            "network": s.network,
            "transport": s.transport,
            "protocol": s.protocol_text(),
            "src": s.src,
            "dst": s.dst,
            "srcPort": s.src_port,
            "dstPort": s.dst_port,
            "srcEndpoint": f"{s.src}:{s.src_port}" if s.src_port else s.src,
            "dstEndpoint": f"{s.dst}:{s.dst_port}" if s.dst_port else s.dst,
            "info": s.info,
        })
        idx += 1
    return metadata, packets


def analyse_pcap(path: pathlib.Path, engine: IDSEngine) -> list[Alert]:
    print(f"\n{'='*70}")
    print(f"  IDS Analysis: {path.name}")
    print(f"{'='*70}")
    _, packets = read_pcap_packets(path)
    print(f"  Loaded {len(packets)} packets\n")
    all_alerts: list[Alert] = []
    for pkt in packets:
        all_alerts.extend(engine.inspect(pkt))
    return all_alerts


# ---------------------------------------------------------------------------
# Dashboard JS output
# ---------------------------------------------------------------------------


def write_threats_js(alerts: list[Alert], out_path: pathlib.Path) -> None:
    """Write ids_threats.js so network_dashboard.html can show the IDS panel."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.severity, 9))

    # Summary counts
    counts: dict[str, int] = collections.Counter(a.severity for a in alerts)  # type: ignore[assignment]
    rule_counts: dict[str, int] = collections.Counter(a.rule for a in alerts)  # type: ignore[assignment]
    attacker_counts: dict[str, int] = collections.Counter(a.src_ip for a in alerts)  # type: ignore[assignment]

    payload = {
        "generatedAt": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "totalAlerts": len(alerts),
        "bySeverity": {k: counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "byRule": [{"rule": r, "count": c} for r, c in sorted(rule_counts.items(), key=lambda x: -x[1])],
        "topAttackers": [{"ip": ip, "count": c} for ip, c in sorted(attacker_counts.items(), key=lambda x: -x[1])[:10]],
        "alerts": [a.to_dict() for a in sorted_alerts],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(payload, indent=2, sort_keys=False)
    out_path.write_text("window.IDS_THREAT_DATA = " + json_text + ";\n", encoding="utf-8")
    print(f"\n  Dashboard threat data  → {out_path}")


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------


def print_summary(alerts: list[Alert]) -> None:
    print(f"\n{'='*70}")
    print("  IDS SUMMARY")
    print(f"{'='*70}")
    if not alerts:
        print("  No threats detected.")
        return

    by_sev: dict[str, list[Alert]] = collections.defaultdict(list)
    for a in alerts:
        by_sev[a.severity].append(a)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if by_sev[sev]:
            print(_color(sev, f"  {sev}: {len(by_sev[sev])} alert(s)"))
            for a in by_sev[sev]:
                ts = dt.datetime.fromtimestamp(a.timestamp).strftime("%H:%M:%S")
                print(f"    [{ts}] {a.rule:<22} {a.src_ip} → {a.detail}")

    print(f"\n  Total: {len(alerts)} alert(s) across {len(set(a.rule for a in alerts))} rule(s)")


# ---------------------------------------------------------------------------
# Live capture integration
# ---------------------------------------------------------------------------


def live_capture_and_analyse(args: argparse.Namespace, engine: IDSEngine) -> list[Alert]:
    """Run packet_capture live, feed each packet to the IDS engine in real-time."""
    import scapy.all as scapy  # type: ignore

    output_path = pathlib.Path(args.output) if args.output else None
    writer = None
    if output_path:
        from packet_capture import PcapWriter
        writer = PcapWriter(str(output_path), linktype=1)

    packet_count = 0
    all_alerts: list[Alert] = []
    start = time.monotonic()

    print(f"\n{'='*70}")
    print("  IDS Live Capture")
    print(f"  duration={args.duration or '∞'}s  interface={args.interface or 'default'}")
    print(f"{'='*70}\n")

    def handle(pkt):
        nonlocal packet_count
        packet_count += 1
        ts = float(getattr(pkt, "time", time.time()))
        if pkt.haslayer(scapy.Ether):
            raw = bytes(pkt)
            lt = 1
        else:
            raw = bytes(pkt[scapy.IP]) if pkt.haslayer(scapy.IP) else bytes(pkt)
            lt = 101
        summary = CAPTURE.decode_packet(raw, timestamp=ts, linktype=lt)
        if writer:
            writer.write(raw, ts)
        pkt_dict = {
            "index": packet_count,
            "timestamp": ts,
            "time": dt.datetime.fromtimestamp(ts).isoformat(timespec="milliseconds"),
            "length": summary.length,
            "layer2": summary.layer2,
            "network": summary.network,
            "transport": summary.transport,
            "protocol": summary.protocol_text(),
            "src": summary.src,
            "dst": summary.dst,
            "srcPort": summary.src_port,
            "dstPort": summary.dst_port,
            "srcEndpoint": f"{summary.src}:{summary.src_port}" if summary.src_port else summary.src,
            "dstEndpoint": f"{summary.dst}:{summary.dst_port}" if summary.dst_port else summary.dst,
            "info": summary.info,
        }
        new_alerts = engine.inspect(pkt_dict)
        all_alerts.extend(new_alerts)

    try:
        scapy.sniff(
            iface=args.interface,
            count=args.count or 0,
            timeout=args.duration or None,
            prn=handle,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n  Capture stopped by user.")
    finally:
        if writer:
            writer.close()

    elapsed = time.monotonic() - start
    print(f"\n  Captured {packet_count} packet(s) in {elapsed:.1f}s")
    return all_alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Network Intrusion Detection System – detect, alert, and respond.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Mode
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("pcap", nargs="?", type=pathlib.Path,
                      help="Analyse an existing .pcap file")
    mode.add_argument("--live", action="store_true",
                      help="Run a live capture and analyse in real-time")

    # Live options
    p.add_argument("-i", "--interface", help="Network interface for live capture")
    p.add_argument("-d", "--duration", type=int, default=0,
                   help="Live capture duration in seconds (0 = unlimited)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Max packets for live capture (0 = unlimited)")
    p.add_argument("-o", "--output", help="Save live capture to this .pcap file")

    # Output
    p.add_argument("--alert-log", type=pathlib.Path, default=pathlib.Path("ids_alerts.log"),
                   help="Plain-text alert log file")
    p.add_argument("--threats-js", type=pathlib.Path, default=pathlib.Path("ids_threats.js"),
                   help="Dashboard JavaScript file for threat visualisation")
    p.add_argument("--quiet", action="store_true", help="Suppress terminal alert output")

    # Response
    p.add_argument("--block-firewall", action="store_true",
                   help="Block attacker IPs via Windows Firewall (requires Admin)")
    p.add_argument("--block-hosts", type=pathlib.Path,
                   help="Append attacker IPs to this hosts-file block list")

    # Threshold tuning
    p.add_argument("--portscan-ports", type=int, default=15)
    p.add_argument("--portscan-window", type=float, default=5.0)
    p.add_argument("--synflood-count", type=int, default=30)
    p.add_argument("--synflood-window", type=float, default=3.0)
    p.add_argument("--icmpflood-count", type=int, default=20)
    p.add_argument("--icmpflood-window", type=float, default=3.0)
    p.add_argument("--bruteforce-count", type=int, default=10)
    p.add_argument("--bruteforce-window", type=float, default=5.0)
    p.add_argument("--dnstunnel-count", type=int, default=15)
    p.add_argument("--dnstunnel-window", type=float, default=5.0)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    thresholds = Thresholds(
        portscan_ports=args.portscan_ports,
        portscan_window=args.portscan_window,
        synflood_count=args.synflood_count,
        synflood_window=args.synflood_window,
        icmpflood_count=args.icmpflood_count,
        icmpflood_window=args.icmpflood_window,
        bruteforce_count=args.bruteforce_count,
        bruteforce_window=args.bruteforce_window,
        dnstunnel_count=args.dnstunnel_count,
        dnstunnel_window=args.dnstunnel_window,
    )

    engine = IDSEngine(
        thresholds=thresholds,
        alert_log=args.alert_log,
        block_firewall=args.block_firewall,
        block_hosts=args.block_hosts,
        quiet=args.quiet,
    )

    try:
        if args.live:
            alerts = live_capture_and_analyse(args, engine)
        elif args.pcap:
            alerts = analyse_pcap(args.pcap, engine)
        else:
            parser.error("Provide a .pcap file to analyse, or use --live for live capture.")
            return 1
    finally:
        engine.close()

    print_summary(alerts)

    if args.threats_js:
        write_threats_js(alerts, args.threats_js)

    if args.alert_log and alerts:
        print(f"  Alert log                → {args.alert_log}")

    print()
    return 0 if not alerts else 1


if __name__ == "__main__":
    raise SystemExit(main())
