"""
main.py
CLI entry point for the Network Traffic Analyzer.

Usage:
    python3 main.py ../data/sample_capture.pcap
    python3 main.py ../data/sample_capture.pcap --report
"""
import argparse
import pcap_parser
import analyzer
import report

GREEN = "\033[92m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = rf"""{GREEN}{BOLD}
 _____           __  __ _        _                _
|_   _| __ __ _ / _|/ _(_) ___  / \   _ __   __ _| |_   _ _______ _ __
  | || '__/ _` | |_| |_| |/ __|/ _ \ | '_ \ / _` | | | | |_  / _ \ '__|
  | || | | (_| |  _|  _| | (__/ ___ \| | | | (_| | | |_| |/ /  __/ |
  |_||_|  \__,_|_| |_| |_|\___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
{RESET}{DIM}         from-scratch .pcap parser & analyzer          |___/{RESET}
"""

SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW}


def main():
    parser_ = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser_.add_argument("pcap_file", help="Path to a .pcap file")
    parser_.add_argument("--report", action="store_true", help="Generate an HTML report")
    args = parser_.parse_args()

    print(BANNER)
    print(f"{GREEN}[*]{RESET} Reading: {args.pcap_file}\n")

    packets = list(pcap_parser.read_pcap(args.pcap_file))
    summary = analyzer.summarize(packets)

    print(f"{BOLD}Total packets:{RESET} {summary['total_packets']}   "
          f"{BOLD}IPv4 packets:{RESET} {summary['ipv4_packets']}\n")

    print(f"{BOLD}Protocol breakdown:{RESET}")
    for proto, count in summary["protocol_counts"].items():
        print(f"  {GREEN}{proto:6}{RESET} {count}")

    print(f"\n{BOLD}Top talkers (by source IP):{RESET}")
    for ip, count in summary["top_talkers"]:
        print(f"  {GREEN}{ip:16}{RESET} {count} packets")

    print(f"\n{BOLD}Top destination ports:{RESET}")
    for port, count in summary["top_dest_ports"]:
        print(f"  {GREEN}{port:6}{RESET} {count} packets")

    alerts = analyzer.detect_port_scan(packets) + analyzer.detect_syn_flood(packets)
    if alerts:
        print(f"\n{YELLOW}{BOLD}[!] Alerts:{RESET}")
        for a in alerts:
            color = SEV_COLOR.get(a["severity"], DIM)
            print(f"  {color}[{a['severity']}]{RESET} {a['type']:12} {a['message']}")
    else:
        print(f"\n{GREEN}[+] No anomalies detected.{RESET}")

    if args.report:
        path = report.generate_html_report(args.pcap_file, summary, alerts)
        print(f"\n{GREEN}[*] HTML report written to: {path}{RESET}")


if __name__ == "__main__":
    main()
