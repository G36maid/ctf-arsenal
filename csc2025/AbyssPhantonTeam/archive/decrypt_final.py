#!/usr/bin/env python3
from Crypto.Cipher import AES
import re

with open("dist/ghost", "rb") as f:
    ciphertext = f.read()

key = b"winniepooh"
key_padded = key + b"\x00" * (16 - len(key))

print(f"Key: {key.decode()}")
print(f"Ciphertext size: {len(ciphertext)} bytes")

iv = ciphertext[:16]
data = ciphertext[16:]

modes = [
    ("CFB", AES.MODE_CFB),
    ("CBC", AES.MODE_CBC),
    ("CTR", AES.MODE_CTR),
]

for mode_name, mode in modes:
    try:
        if mode == AES.MODE_CTR:
            from Crypto.Util import Counter

            ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key_padded, mode, counter=ctr)
        elif mode == AES.MODE_CFB:
            cipher = AES.new(key_padded, mode, iv, segment_size=128)
        else:
            cipher = AES.new(key_padded, mode, iv)

        plaintext = cipher.decrypt(data)

        if plaintext[:2] == b"MZ":
            print(f"\n✓ SUCCESS with {mode_name}!")
            print(f"First 64 bytes: {plaintext[:64].hex()}")

            output = f"dist/decrypted_{mode_name.lower()}.bin"
            with open(output, "wb") as f:
                f.write(plaintext)
            print(f"Saved to {output}")

            matches = re.findall(rb"CSC\{[^}]+\}", plaintext)
            if matches:
                print(f"\n🚩 FLAGS FOUND:")
                for m in matches:
                    print(f"  {m.decode()}")
            else:
                print("\nNo CSC{} flag in decrypted PE")
                print("This PE likely needs to be executed to reveal the flag")
            break
    except Exception as e:
        print(f"{mode_name} failed: {e}")
