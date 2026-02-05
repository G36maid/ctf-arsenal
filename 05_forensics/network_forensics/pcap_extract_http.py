#!/usr/bin/env python3
"""
PCAP HTTP Extraction - Extract HTTP streams, payloads, and files from network captures.

Usage:
    python pcap_extract_http.py <pcap_file> [output_dir]

Extracts:
    - HTTP requests (headers, parameters)
    - HTTP responses (bodies)
    - Reconstructed files from HTTP transfers
    - DNS queries

Dependencies:
    pip install scapy dpkt
    Or use tshark (part of wireshark package)
"""

import sys
import os
import subprocess
from collections import defaultdict


def extract_with_tshark(pcap_file, output_dir):
    """Use tshark (preferred - more reliable)."""
    print("[*] Using tshark for extraction (more reliable)...")

    # Extract HTTP requests
    print("\n[*] Extracting HTTP Requests:")
    cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "http.request.method",
        "-e",
        "http.host",
        "-e",
        "http.request.uri",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout:
            print(result.stdout[:1000])  # First 1000 chars
            # Save to file
            with open(os.path.join(output_dir, "http_requests.txt"), "w") as f:
                f.write(result.stdout)
            print(f"[+] Saved to {output_dir}/http_requests.txt")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[-] tshark failed: {e}")
        return False

    # Extract HTTP response bodies
    print("\n[*] Extracting HTTP Response Bodies:")
    cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "http.response",
        "-T",
        "fields",
        "-e",
        "http.response.code",
        "-e",
        "http.content_type",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout:
            print(result.stdout[:500])
            with open(os.path.join(output_dir, "http_responses.txt"), "w") as f:
                f.write(result.stdout)
            print(f"[+] Saved to {output_dir}/http_responses.txt")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[-] tshark failed: {e}")

    # Extract DNS queries
    print("\n[*] Extracting DNS Queries:")
    cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "dns.flags.response == 0",
        "-T",
        "fields",
        "-e",
        "dns.qry.name",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout:
            unique_queries = set(result.stdout.strip().split("\n"))
            print(f"[+] Found {len(unique_queries)} unique DNS queries:")
            for query in list(unique_queries)[:10]:
                if query:
                    print(f"    {query}")
            with open(os.path.join(output_dir, "dns_queries.txt"), "w") as f:
                f.write("\n".join(unique_queries))
            print(f"[+] Saved to {output_dir}/dns_queries.txt")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[-] tshark failed: {e}")

    return True


def extract_with_tcpflow(pcap_file, output_dir):
    """Use tcpflow to reconstruct TCP streams."""
    print("\n[*] Using tcpflow to reconstruct TCP streams...")
    flow_dir = os.path.join(output_dir, "tcpflow_output")

    cmd = ["tcpflow", "-r", pcap_file, "-o", flow_dir]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode == 0:
            print(f"[+] TCP streams reconstructed in {flow_dir}")
            # List extracted files
            if os.path.exists(flow_dir):
                files = os.listdir(flow_dir)
                print(f"[+] Found {len(files)} stream files:")
                for f in files[:10]:
                    size = os.path.getsize(os.path.join(flow_dir, f))
                    print(f"    {f} ({size} bytes)")
    except FileNotFoundError:
        print("[-] tcpflow not found (install: apt install tcpflow)")
    except subprocess.TimeoutExpired:
        print("[-] tcpflow timeout")


def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_extract_http.py <pcap_file> [output_dir]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "pcap_extraction"

    if not os.path.exists(pcap_file):
        print(f"[-] PCAP file not found: {pcap_file}")
        sys.exit(1)

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] PCAP Extraction: {pcap_file}")
    print(f"[*] Output directory: {output_dir}")
    print("=" * 60)

    # Try tshark first (most reliable)
    success = extract_with_tshark(pcap_file, output_dir)

    # Also try tcpflow for TCP stream reconstruction
    extract_with_tcpflow(pcap_file, output_dir)

    if not success:
        print("\n[!] Warning: tshark not available")
        print("    Install: apt install wireshark-common")
        print("    Or use: wireshark <pcap_file> (GUI)")

    print("\n" + "=" * 60)
    print("[+] Extraction complete")
    print("\n[*] For more analysis, try:")
    print("    - Inspect HTTP payload: xxd pcap_extraction/http_responses.txt")
    print("    - Check DNS for C2 domains: cat pcap_extraction/dns_queries.txt")
    print("    - Find binary files: file pcap_extraction/tcpflow_output/*")


if __name__ == "__main__":
    main()
