# Network Traffic Analyzer

A from-scratch `.pcap` file parser and traffic analyzer — no scapy/dpkt
dependency. Parses the libpcap binary format, Ethernet/IPv4/TCP/UDP headers
byte-by-byte using `struct`, then flags port-scan and SYN-flood patterns.

![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

> This tool analyzes previously captured `.pcap` files — it does not
> perform live packet capture (which requires elevated privileges and raw
> sockets). Use it on your own lab captures or publicly available sample
> pcaps (e.g. Wireshark's sample capture library).

## What it does

1. **`pcap_parser.py`** — reads the libpcap file format's global header and
   per-packet records, then parses each Ethernet frame → IPv4 header →
   TCP/UDP header, extracting source/destination IPs, ports, and TCP flags —
   entirely with `struct.unpack`, the same way you'd read a hex dump by hand.
2. **`analyzer.py`**
   - Protocol breakdown, top talkers, top destination ports
   - **Port scan detection**: flags a source IP sending SYN packets to many
     distinct destination ports (the packet-level version of the recon
     pattern `port-scanner` in this portfolio generates)
   - **SYN flood detection**: flags a source sending an abnormal volume of
     SYN packets to one destination
3. **`sample_pcap_generator.py`** — builds a small, valid synthetic `.pcap`
   file (also byte-by-byte, no library) with normal traffic plus embedded
   port-scan and SYN-flood patterns, so the analyzer can be demoed without
   needing a real capture.
4. **`main.py` / `report.py`** — CLI + HTML report export.

## Quick start

```bash
cd src
python3 sample_pcap_generator.py          # generates ../data/sample_capture.pcap
python3 main.py ../data/sample_capture.pcap
python3 main.py ../data/sample_capture.pcap --report
```

No external dependencies — pure Python standard library (`struct`, `socket`).

## Why this project

Most traffic-analysis tools lean entirely on scapy or dpkt. Building the
`.pcap` and packet parsing from scratch demonstrates actual protocol-level
understanding — what's in an Ethernet frame, how IHL determines where the
IP header ends, how TCP flag bits are packed into a single byte — rather
than just calling a library function.

## Roadmap / ideas for v2

- [ ] IPv6 support
- [ ] Live capture mode (via raw sockets, with appropriate privilege handling)
- [ ] DNS query/response parsing
- [ ] Payload-based signature matching (e.g. plaintext credential detection)

## License

MIT
