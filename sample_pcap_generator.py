"""
sample_pcap_generator.py
Generates a small, valid synthetic .pcap file byte-for-byte (same format
pcap_parser.py reads) so the analyzer can be demoed without needing a real
network capture. Embeds normal traffic plus a port-scan pattern and a
SYN-flood pattern so the detection rules have something to find.

Usage:
    python3 sample_pcap_generator.py
"""
import struct
import socket
import random
import os
import time

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sample_capture.pcap")


def build_global_header():
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # 1 = Ethernet


def build_packet_header(ts, incl_len, orig_len):
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)


def build_ethernet(src_mac, dst_mac, ethertype=0x0800):
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def build_ipv4(src_ip, dst_ip, proto, payload_len, ident=0):
    ihl_words = 5
    ver_ihl = (4 << 4) | ihl_words
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, ident, 0, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return header


def build_tcp(src_port, dst_port, flags, seq=1000, ack=0):
    flag_byte = 0
    for bit, name in [(0, "FIN"), (1, "SYN"), (2, "RST"), (3, "PSH"), (4, "ACK"), (5, "URG")]:
        if name in flags:
            flag_byte |= (1 << bit)
    offset_flags = (5 << 12) | flag_byte  # data offset = 5 words, no options
    return struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)


def build_udp(src_port, dst_port, payload_len=0):
    length = 8 + payload_len
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def make_packet(eth, ip, transport, payload=b""):
    return eth + ip + transport + payload


MAC_A = bytes.fromhex("aabbccddee01")
MAC_B = bytes.fromhex("aabbccddee02")


def generate():
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    packets = []
    t = time.time()

    normal_ips = ["10.0.0.5", "10.0.0.8", "10.0.0.12"]
    server_ip = "10.0.0.1"

    # Normal traffic: a handful of TCP handshakes + HTTP/DNS-ish UDP
    for i in range(20):
        src = random.choice(normal_ips)
        eth = build_ethernet(MAC_A, MAC_B)
        ip = build_ipv4(src, server_ip, 6, 20, ident=i)
        tcp = build_tcp(random.randint(40000, 60000), random.choice([80, 443]), "SYN", seq=1000 + i)
        packets.append((t + i * 0.5, make_packet(eth, ip, tcp)))

    for i in range(10):
        src = random.choice(normal_ips)
        eth = build_ethernet(MAC_A, MAC_B)
        ip = build_ipv4(src, "10.0.0.2", 17, 8, ident=100 + i)
        udp = build_udp(random.randint(40000, 60000), 53)
        packets.append((t + 15 + i * 0.3, make_packet(eth, ip, udp)))

    # Port scan pattern: one attacker IP hitting many distinct ports on the server
    attacker = "203.0.113.99"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    for i, port in enumerate(scan_ports):
        eth = build_ethernet(MAC_A, MAC_B)
        ip = build_ipv4(attacker, server_ip, 6, 20, ident=200 + i)
        tcp = build_tcp(random.randint(40000, 60000), port, "SYN", seq=5000 + i)
        packets.append((t + 20 + i * 0.05, make_packet(eth, ip, tcp)))

    # SYN flood pattern: one source hammering one port with SYNs
    flooder = "198.51.100.50"
    for i in range(60):
        eth = build_ethernet(MAC_A, MAC_B)
        ip = build_ipv4(flooder, server_ip, 6, 20, ident=300 + i)
        tcp = build_tcp(random.randint(40000, 60000), 443, "SYN", seq=9000 + i)
        packets.append((t + 25 + i * 0.02, make_packet(eth, ip, tcp)))

    packets.sort(key=lambda x: x[0])

    with open(OUT_PATH, "wb") as f:
        f.write(build_global_header())
        for ts, data in packets:
            f.write(build_packet_header(ts, len(data), len(data)))
            f.write(data)

    print(f"Wrote {len(packets)} packets to {OUT_PATH}")


if __name__ == "__main__":
    random.seed(7)
    generate()
