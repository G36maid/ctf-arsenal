#!/usr/bin/env python3
"""
IEC 104 packet sniffer.
Captures and decodes IEC 104 protocol traffic.

Usage:
    sudo python iec104_sniffer.py [filter_expression]

Example:
    sudo python iec104_sniffer.py "tcp port 2404"
"""

from scapy.all import *


def process_packet(pkt):
    """Process and decode IEC 104 packets."""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if dport == 2404 or sport == 2404:
            raw_data = bytes(pkt[Raw].load)
            if len(raw_data) >= 6:
                apci_type = raw_data[2] if len(raw_data) > 2 else 0

                print(f"\n[IEC 104] {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}")
                print(f"  Len={len(raw_data)} APCI_Type=0x{apci_type:02x}")

                # Identify APCI type
                if apci_type == 0x00:
                    print(f"  Type: I-Frame (Info)")
                elif apci_type == 0x40:
                    print(f"  Type: S-Frame (Supervise)")
                elif apci_type in [0x80, 0xC0]:
                    print(f"  Type: U-Frame (Unnumbered)")

                if apci_type in [0x64, 0x65]:
                    print(f"  [!] COMMAND DETECTED")

                print(f"  Hex: {raw_data.hex()}")


if __name__ == "__main__":
    filter_str = "tcp port 2404"
    print("[*] IEC 104 Sniffer - Capturing traffic...")
    print(f"[*] Filter: {filter_str}")
    sniff(filter=filter_str, prn=process_packet, store=0)
