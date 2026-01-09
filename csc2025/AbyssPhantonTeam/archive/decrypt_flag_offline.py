#!/usr/bin/env python3
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("flag_encrypted.bin", "rb") as f:
    iv = f.read(16)
    encrypted = f.read()

print(f"IV: {iv.hex()}")
print(f"Encrypted data: {encrypted.hex()}")
print(f"Encrypted length: {len(encrypted)}")
print()

SALT = b"CSC_KEY_DERIVATION_SALT_2024"


def try_password(pwd):
    if isinstance(pwd, str):
        pwd = pwd.encode("utf-8")

    key = hashlib.sha256(pwd + SALT).digest()

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(encrypted)

        plaintext_unpadded = unpad(plaintext, AES.block_size)

        if b"CSC{" in plaintext_unpadded or b"FLAG{" in plaintext_unpadded:
            return True, plaintext_unpadded.decode("utf-8", errors="ignore")

        if plaintext_unpadded.isascii() and len(plaintext_unpadded) > 10:
            return True, plaintext_unpadded.decode("utf-8")

    except Exception as e:
        pass

    return False, None


candidates = [
    "CSC2250PASSWORD",
    "CSC2250PASSW0RD",
    "CSC2250APSSWORD",
    "CSC2250APSSWODR",
    "CSC2250PASSWODR",
]

print("[*] Testing password candidates...")
for pwd in candidates:
    success, result = try_password(pwd)
    if success:
        print(f"\n{'=' * 70}")
        print(f"[+] FOUND FLAG with password: {pwd}")
        print(f"{'=' * 70}")
        print(f"Flag: {result}")
        print(f"{'=' * 70}")
        break
    else:
        print(f"[-] Failed: {pwd}")

print("\n[*] Testing variations...")
base_patterns = ["CSC", "ABC", "AAA"]
for base in base_patterns:
    for d1 in "0123456789":
        for d2 in "0123456789":
            pwd = f"{base}{base[2]}{d1}{d1}{d2}0PASSWORD"
            if len(pwd) == 15:
                success, result = try_password(pwd)
                if success:
                    print(f"\n[+] FOUND: {pwd}")
                    print(f"Flag: {result}")
                    break
