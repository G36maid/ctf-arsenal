#!/usr/bin/env python3
"""
TimeSpy - RC4 encryption challenge solver
The binary uses RC4 with a derived key to encrypt the flag.
"""

import struct

# Encrypted flag from binary (address 0x11b52d5)
enc_flag_bytes = bytes.fromhex(
    "627c9edd242f177d16cbfa9a518cee1ecd650fa8b046e23ba91a271eb6"
)

print(f"[*] Encrypted flag length: {len(enc_flag_bytes)} bytes")
print(f"[*] Encrypted flag (hex): {enc_flag_bytes.hex()}")

key = bytes.fromhex("415f47303044_5f533133455003030303".replace("_", ""))
print(f"\n[*] Extracted RC4 key from GDB: {key.hex()}")
print(f"[*] Key (ASCII): {key[:12]}")


def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S, data):
    """RC4 Pseudo-Random Generation Algorithm"""
    i = 0
    j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)


def rc4_crypt(key, data):
    """Full RC4 encryption/decryption"""
    S = rc4_ksa(key)
    return rc4_prga(S, data)


# Decrypt the flag
print("\n[*] Decrypting flag with RC4...")
flag = rc4_crypt(key, enc_flag_bytes)

print(f"[+] Decrypted flag (hex): {flag.hex()}")
print(f"[+] Decrypted flag: {flag}")

# Try to decode as ASCII
try:
    flag_str = flag.decode("ascii")
    print(f"\n[SUCCESS] Flag: {flag_str}")
except:
    print(f"\n[!] Flag is not valid ASCII, raw bytes: {flag}")
