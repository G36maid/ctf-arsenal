#!/usr/bin/env python3
import hashlib
import subprocess
import sys

with open("flag_encrypted.bin", "rb") as f:
    iv = f.read(16)
    encrypted = f.read()

print(f"IV: {iv.hex()}")
print(f"Encrypted data: {encrypted.hex()}")
print(f"Encrypted length: {len(encrypted)}")
print()

SALT = b"CSC_KEY_DERIVATION_SALT_2024"


def try_password_openssl(pwd):
    if isinstance(pwd, str):
        pwd = pwd.encode("utf-8")

    key = hashlib.sha256(pwd + SALT).digest()

    with open("/tmp/key.bin", "wb") as f:
        f.write(key)

    with open("/tmp/iv.bin", "wb") as f:
        f.write(iv)

    with open("/tmp/enc.bin", "wb") as f:
        f.write(encrypted)

    result = subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-in",
            "/tmp/enc.bin",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nopad",
        ],
        capture_output=True,
    )

    if result.returncode == 0:
        plaintext = result.stdout

        if b"CSC{" in plaintext or b"FLAG{" in plaintext or b"flag{" in plaintext:
            return True, plaintext.decode("utf-8", errors="ignore")

        try:
            text = plaintext.decode("utf-8")
            if text.isprintable() and len(text) > 10:
                return True, text
        except:
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
    print(f"[*] Trying: {pwd}")
    success, result = try_password_openssl(pwd)
    if success:
        print(f"\n{'=' * 70}")
        print(f"[+] FOUND FLAG with password: {pwd}")
        print(f"{'=' * 70}")
        print(f"Flag: {result}")
        print(f"{'=' * 70}")
        sys.exit(0)

print("\n[!] No flag found with known candidates")
