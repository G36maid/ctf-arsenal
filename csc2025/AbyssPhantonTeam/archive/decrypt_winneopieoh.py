#!/usr/bin/env python3
"""
Decrypt ghost file using the key "winneopieoh" from decompiled code.
"""

import struct


# Simple AES CFB implementation using only standard library
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# Read the encrypted file
with open("dist/ghost", "rb") as f:
    ciphertext = f.read()

# Key from decompiled code at lines 357-358 in main.main:
# *(undefined8 *)(iVar82 + 0x46) = 0x6f7065696e6e6977;  # "winneopie" in little endian -> "winneopie" reversed
# *(undefined2 *)(iVar82 + 0x4e) = 0x686f;               # "ho" in little endian -> "oh" reversed

# Let's decode the hex values properly
hex1 = 0x6F7065696E6E6977  # 8 bytes
hex2 = 0x686F  # 2 bytes

# Convert to bytes (little endian as it's x86-64)
key_part1 = struct.pack("<Q", hex1)  # 8 bytes
key_part2 = struct.pack("<H", hex2)  # 2 bytes

key = key_part1 + key_part2  # 10 bytes total

print(f"Extracted key (10 bytes): {key}")
print(f"Key as string: {key.decode('latin-1')}")
print(f"Ciphertext size: {len(ciphertext)} bytes")

# For AES, we need to pad the key to 16 bytes
key_padded = key + b"\x00" * (16 - len(key))
print(f"Padded key (16 bytes, hex): {key_padded.hex()}")

# We need crypto library for AES - let's try using existing decrypted file
# and analyze it instead

print("\nTrying to use openssl command...")
import subprocess
import os

# Save key to temp file
with open("/tmp/aes_key.bin", "wb") as f:
    f.write(key_padded)

# Try AES-CFB decryption using openssl
modes = ["aes-128-cfb", "aes-128-cbc", "aes-128-ctr", "aes-128-ecb"]

for mode in modes:
    print(f"\nTrying {mode}...")
    try:
        # Extract IV (first 16 bytes)
        iv = ciphertext[:16]
        data = ciphertext[16:]

        # Write encrypted data
        with open("/tmp/encrypted.bin", "wb") as f:
            f.write(data)

        # Try decryption
        if mode.endswith("-ecb"):
            cmd = f"openssl enc -{mode} -d -in /tmp/encrypted.bin -out /tmp/decrypted.bin -K {key_padded.hex()} -nopad"
        else:
            cmd = f"openssl enc -{mode} -d -in /tmp/encrypted.bin -out /tmp/decrypted.bin -K {key_padded.hex()} -iv {iv.hex()} -nopad"

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            with open("/tmp/decrypted.bin", "rb") as f:
                plaintext = f.read()

            if plaintext[:2] == b"MZ":
                print(f"✓ SUCCESS with {mode}!")
                print(f"First 32 bytes: {plaintext[:32].hex()}")

                # Save result
                output = f"dist/decrypted_{mode.replace('-', '_')}.bin"
                with open(output, "wb") as f:
                    f.write(plaintext)
                print(f"Saved to {output}")

                # Search for flag
                import re

                matches = re.findall(rb"CSC\{[^}]+\}", plaintext)
                if matches:
                    print(f"\n🚩 FLAGS FOUND:")
                    for m in matches:
                        print(f"  {m.decode()}")
                    break
                else:
                    # Check with strings
                    result = subprocess.run(
                        ["strings", output], capture_output=True, text=True
                    )
                    for line in result.stdout.split("\n"):
                        if "CSC{" in line or "FLAG{" in line:
                            print(f"String match: {line}")
    except Exception as e:
        print(f"Error: {e}")

print("\nDone!")
