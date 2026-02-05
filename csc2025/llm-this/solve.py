#!/usr/bin/env python3
import struct

# Encrypted flag data from disassembly (little-endian)
part1 = struct.pack('<Q', 0x300c420103315a3b)
part2 = struct.pack('<Q', 0x15431b27015e1006)
part3 = struct.pack('<H', 0x0f5c)

enc_flag = part1 + part2 + part3

# Key from binary
key = b'xor'

# Flag length
flag_len = 0x12  # 18 bytes

print(f"Encrypted flag (hex): {enc_flag.hex()}")
print(f"Key: {key}")

# XOR decrypt
flag = bytearray()
for i in range(flag_len):
    flag.append(enc_flag[i] ^ key[i % len(key)])

print(f"Flag: {flag.decode()}")
