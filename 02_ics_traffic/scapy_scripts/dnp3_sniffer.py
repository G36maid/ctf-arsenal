#!/usr/bin/env python3
"""
DNP3 packet sniffer.
Captures and decodes DNP3 protocol traffic on port 20000.

Usage:
    sudo python dnp3_sniffer.py

Example:
    sudo python dnp3_sniffer.py
"""

from scapy.all import *


def process_packet(pkt):
    """Process and decode DNP3 packets."""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if dport == 20000 or sport == 20000:
            raw_data = bytes(pkt[Raw].load)
            if len(raw_data) >= 5:
                # DNP3 starts with 0x0564 (sync bytes)
                if raw_data[0:2] == b"\x05\x64":
                    print(f"\n[DNP3] {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}")

                    # Parse DNP3 header
                    length = int.from_bytes(raw_data[2:4], "big")
                    control = raw_data[4]

                    print(f"  Len={length} Control=0x{control:02x}")

                    # Identify frame type
                    if control & 0x80:
                        if control & 0x40:
                            print(f"  Type: Secondary Station Response")
                        else:
                            print(f"  Type: Primary Station Command")

                    # Check for control (unsolicited, select/operate, etc)
                    if control & 0x08:
                        print(f"  [!] CONTROL/COMMAND DETECTED")

                    print(f"  Hex: {raw_data[: min(30, len(raw_data))].hex()}...")


if __name__ == "__main__":
    filter_str = "tcp port 20000"
    print("[*] DNP3 Sniffer - Capturing traffic...")
    print(f"[*] Filter: {filter_str}")
    sniff(filter=filter_str, prn=process_packet, store=0)
