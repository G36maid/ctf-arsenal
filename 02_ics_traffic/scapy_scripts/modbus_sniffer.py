#!/usr/bin/env python3
from scapy.all import *


def process_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if dport == 502 or sport == 502:
            raw_data = bytes(pkt[Raw].load)
            if len(raw_data) >= 8:
                transaction_id = int.from_bytes(raw_data[0:2], "big")
                protocol_id = int.from_bytes(raw_data[2:4], "big")
                length = int.from_bytes(raw_data[4:6], "big")
                unit_id = raw_data[6]
                function_code = raw_data[7]

                print(f"[Modbus] {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}")
                print(f"  TID={transaction_id} Unit={unit_id} Func={function_code}")

                if function_code in [5, 6, 15, 16]:
                    print(f"  [!] WRITE operation detected!")

                print(f"  Data: {raw_data.hex()}")


sniff(filter="tcp port 502", prn=process_packet, store=0)
