#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

iv = bytes.fromhex("1a2b3c4d5e6f8091a2b3c4d5e6f70819")
encrypted = bytes.fromhex(
    "63843b54a77aa6f73f5e2faa93c08192"
    "fd665009dfc79fdc033cc92686eb5cff"
    "385810be6de7f02689f78a85df8e21ea"
    "cde2bcf662d848923f7d133ea78ab566"
)

salt = b"CSC_KEY_DERIVATION_SALT_2024"

passwords = [
    "CSC2025PASSPHRASE",
    "CSC2025PASSWORD",
    "CSC2025PHANTOM",
    "CSC2025ABYSSSS",
    "CSC2025ABYSSAL",
    "CSCPASS2025WORD",
    "CSC2025WORDPAS",
    "AAA0000AAAAAAAA",
    "CSC2025PASSPHR",
]

for pwd in passwords:
    try:
        key_material = pwd.encode() + salt
        key = hashlib.sha256(key_material).digest()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        decrypted_unpadded = unpad(decrypted, AES.block_size)

        if decrypted_unpadded.startswith(b"CSC{") and decrypted_unpadded.endswith(b"}"):
            print(f"[+] PASSWORD: {pwd}")
            print(f"[+] FLAG: {decrypted_unpadded.decode()}")
            break
        elif b"CSC" in decrypted_unpadded or b"FLAG" in decrypted_unpadded:
            print(f"[?] Password '{pwd}' gave partial match:")
            print(f"    {decrypted_unpadded}")
    except Exception as e:
        continue

print("[-] None of the test passwords worked")
