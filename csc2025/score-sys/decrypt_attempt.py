#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

# The target ciphertext (Admin password)
b64_cipher = "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM"
# Correct Base64 padding
missing_padding = len(b64_cipher) % 4
if missing_padding:
    b64_cipher += "=" * (4 - missing_padding)

# Decode URL-safe base64
ciphertext = base64.urlsafe_b64decode(b64_cipher)
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Ciphertext length: {len(ciphertext)} bytes")

# Possible Keys
uuid_full = "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"
uuid_simple = uuid_full.replace("-", "")  # 32 chars
keys_to_try = [
    uuid_simple.encode(),  # 32 bytes
    uuid_full.encode()[:32],  # First 32 bytes
    uuid_full.encode()[:16],  # First 16 bytes (AES-128)
    b"score-sys-secret",  # Guess
    b"8d7a77ae-dac9-43",  # First 16 of UUID
]


def decrypt_aes(ct, key, mode=AES.MODE_ECB, iv=None):
    try:
        if mode == AES.MODE_ECB:
            cipher = AES.new(key, mode)
        elif mode == AES.MODE_CBC:
            cipher = AES.new(key, mode, iv)

        pt = cipher.decrypt(ct)
        return pt
    except Exception as e:
        return None


print("\n--- Attempting Decryption ---")
for key in keys_to_try:
    # ECB
    pt = decrypt_aes(ciphertext, key, AES.MODE_ECB)
    if pt:
        print(f"Key: {key}\n  ECB Decrypted: {pt} (Hex: {pt.hex()})")
        # Check for flag format
        if b"CSC" in pt or b"flag" in pt or b"{" in pt:
            print("  [!!!] POSSIBLE FLAG FOUND")

    # CBC (IV is usually first block, but here ct is 32 bytes, maybe IV is separate or all zeros?)
    # If IV is all zeros
    pt = decrypt_aes(ciphertext, key, AES.MODE_CBC, iv=b"\x00" * 16)
    if pt:
        print(f"Key: {key}\n  CBC (Zero IV) Decrypted: {pt}")

# Try XOR
print("\n--- Attempting XOR ---")
for key in keys_to_try:
    try:
        # Cycle key
        xored = bytes(
            a ^ b for a, b in zip(ciphertext, key * (len(ciphertext) // len(key) + 1))
        )
        print(f"Key: {key}\n  XOR Decrypted: {xored}")
    except:
        pass
