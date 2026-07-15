"""
pcap_parser.py
A from-scratch parser for the libpcap file format (.pcap) and the
Ethernet/IPv4/TCP/UDP headers inside it — no scapy/dpkt dependency, just
`struct` and the raw byte layout of each protocol. Built to show the
underlying packet structure, the same way you'd read a hex dump by hand.

Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import struct
import socket
import datetime

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
ETHERNET_HEADER_LEN = 14

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def read_pcap(path):
    """Yields one dict per packet in the file, with parsed headers."""
    with open(path, "rb") as f:
        global_header = f.read(PCAP_GLOBAL_HEADER_LEN)
        if len(global_header) < PCAP_GLOBAL_HEADER_LEN:
            raise ValueError("File too short to be a valid pcap")

        magic = struct.unpack("I", global_header[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            raise ValueError(f"Not a pcap file (bad magic number: {hex(magic)})")

        while True:
            packet_header = f.read(PCAP_PACKET_HEADER_LEN)
            if len(packet_header) < PCAP_PACKET_HEADER_LEN:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            yield parse_packet(data, ts_sec, ts_usec, orig_len)


def parse_packet(data, ts_sec, ts_usec, orig_len):
    packet = {
        "timestamp": datetime.datetime.fromtimestamp(ts_sec).isoformat(),
        "length": orig_len,
        "eth_type": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
    }

    if len(data) < ETHERNET_HEADER_LEN:
        return packet

    eth_type = struct.unpack("!H", data[12:14])[0]
    packet["eth_type"] = hex(eth_type)

    if eth_type != 0x0800:  # not IPv4 — ARP, IPv6, etc. Skip deep parsing.
        return packet

    ip_data = data[ETHERNET_HEADER_LEN:]
    if len(ip_data) < 20:
        return packet

    ver_ihl = ip_data[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = ip_data[9]
    src_ip = socket.inet_ntoa(ip_data[12:16])
    dst_ip = socket.inet_ntoa(ip_data[16:20])

    packet["src_ip"] = src_ip
    packet["dst_ip"] = dst_ip
    packet["protocol"] = IP_PROTOCOLS.get(proto, f"proto-{proto}")

    transport_data = ip_data[ihl:]
    if proto == 6 and len(transport_data) >= 14:  # TCP
        src_port, dst_port = struct.unpack("!HH", transport_data[0:4])
        flags_byte = transport_data[13]
        flag_names = []
        for bit, name in [(0, "FIN"), (1, "SYN"), (2, "RST"), (3, "PSH"), (4, "ACK"), (5, "URG")]:
            if flags_byte & (1 << bit):
                flag_names.append(name)
        packet["src_port"] = src_port
        packet["dst_port"] = dst_port
        packet["tcp_flags"] = ",".join(flag_names)
    elif proto == 17 and len(transport_data) >= 4:  # UDP
        src_port, dst_port = struct.unpack("!HH", transport_data[0:4])
        packet["src_port"] = src_port
        packet["dst_port"] = dst_port

    return packet
