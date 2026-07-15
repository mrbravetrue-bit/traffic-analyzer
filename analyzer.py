"""
analyzer.py
Aggregates parsed packets (from pcap_parser.read_pcap) into summary
statistics and flags simple anomalies — same detection concept as
siem-lite-dashboard's detector.py, applied to raw packet capture instead
of application logs.
"""
from collections import Counter, defaultdict


def summarize(packets):
    packets = list(packets)
    protocol_counts = Counter(p["protocol"] for p in packets if p["protocol"])
    talkers = Counter(p["src_ip"] for p in packets if p["src_ip"])
    dest_ports = Counter(p["dst_port"] for p in packets if p["dst_port"])

    return {
        "total_packets": len(packets),
        "ipv4_packets": sum(1 for p in packets if p["src_ip"]),
        "protocol_counts": dict(protocol_counts),
        "top_talkers": talkers.most_common(10),
        "top_dest_ports": dest_ports.most_common(10),
    }


def detect_port_scan(packets, distinct_port_threshold=10):
    """Flags a source IP that hits many distinct destination ports —
    the packet-level equivalent of the endpoint-scan detection in
    siem-lite-dashboard, but looking at raw SYN packets instead of HTTP logs.
    """
    ports_by_src = defaultdict(set)
    for p in packets:
        if p["protocol"] == "TCP" and p.get("tcp_flags") == "SYN" and p["src_ip"] and p["dst_port"]:
            ports_by_src[p["src_ip"]].add(p["dst_port"])

    alerts = []
    for src_ip, ports in ports_by_src.items():
        if len(ports) >= distinct_port_threshold:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "distinct_ports": len(ports),
                "severity": "HIGH" if len(ports) >= 30 else "MEDIUM",
                "message": f"{src_ip} sent SYN packets to {len(ports)} distinct ports "
                           f"(likely a port scan)",
            })
    return alerts


def detect_syn_flood(packets, threshold=50):
    """Flags a single source sending an unusually large number of SYN
    packets to one destination (SYN flood / DoS-ish pattern)."""
    syn_counts = Counter()
    for p in packets:
        if p["protocol"] == "TCP" and p.get("tcp_flags") == "SYN":
            syn_counts[(p["src_ip"], p["dst_ip"])] += 1

    alerts = []
    for (src, dst), count in syn_counts.items():
        if count >= threshold:
            alerts.append({
                "type": "SYN_FLOOD",
                "src_ip": src,
                "distinct_ports": None,
                "severity": "HIGH",
                "message": f"{src} sent {count} SYN packets to {dst} (possible SYN flood)",
            })
    return alerts
