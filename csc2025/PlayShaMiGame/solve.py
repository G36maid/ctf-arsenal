#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = "info"


def start():
    if args.REMOTE or len(sys.argv) >= 3:
        host = sys.argv[1] if len(sys.argv) >= 2 else "192.168.100.121"
        port = int(sys.argv[2]) if len(sys.argv) >= 3 else 40021
        return remote(host, port)
    else:
        return process(["./game_server.bin"])


io = start()

io.recvuntil(b"Enter your name, Knight:")
io.sendline(b"Hacker")

io.recvuntil(b"Your choice:")
io.sendline(b"3")

io.recvuntil(b"Enter the power calibration value for the energy crystal:")

target_value = 0xB5F72F1DED389973
closest_input = 2090613996

payload = str(closest_input).encode()
io.sendline(payload)

io.interactive()
