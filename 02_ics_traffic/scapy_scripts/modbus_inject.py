#!/usr/bin/env python3
from scapy.all import *
import random

target = "192.168.1.100"
port = 502


def send_modbus_read(address, count):
    transaction_id = random.randint(0, 65535)
    protocol_id = 0
    unit_id = 1
    function_code = 3

    data = bytes(
        [
            (transaction_id >> 8) & 0xFF,
            transaction_id & 0xFF,
            (protocol_id >> 8) & 0xFF,
            protocol_id & 0xFF,
            0x00,
            0x06,
            unit_id,
            function_code,
            (address >> 8) & 0xFF,
            address & 0xFF,
            (count >> 8) & 0xFF,
            count & 0xFF,
        ]
    )

    pkt = (
        IP(dst=target)
        / TCP(dport=port, sport=random.randint(40000, 60000), flags="PA")
        / Raw(load=data)
    )
    send(pkt, verbose=0)
    print(f"[+] Sent read request: addr={address}, count={count}")


def send_modbus_write(address, value):
    transaction_id = random.randint(0, 65535)
    protocol_id = 0
    unit_id = 1
    function_code = 6

    data = bytes(
        [
            (transaction_id >> 8) & 0xFF,
            transaction_id & 0xFF,
            (protocol_id >> 8) & 0xFF,
            protocol_id & 0xFF,
            0x00,
            0x06,
            unit_id,
            function_code,
            (address >> 8) & 0xFF,
            address & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        ]
    )

    pkt = (
        IP(dst=target)
        / TCP(dport=port, sport=random.randint(40000, 60000), flags="PA")
        / Raw(load=data)
    )
    send(pkt, verbose=0)
    print(f"[!] Sent write request: addr={address}, value={value}")


if __name__ == "__main__":
    send_modbus_read(0, 10)
    send_modbus_write(5, 9999)
