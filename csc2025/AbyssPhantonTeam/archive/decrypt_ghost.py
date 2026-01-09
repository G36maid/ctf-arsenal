#!/usr/bin/env python3
"""
Decrypt the ghost file from the Abyss Phantom Team challenge.
The c8763.exe is a Go binary that performs AES decryption.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct
import sys


def try_decrypt_aes(ciphertext, key, iv=None):
    """Try to decrypt with AES-CBC or AES-CTR"""
    results = []

    # Try AES-CBC with PKCS7 padding
    try:
        if iv is None:
            # Use first 16 bytes as IV (common pattern)
            iv = ciphertext[:16]
            data = ciphertext[16:]
        else:
            data = ciphertext

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(data)

        # Check for PE header (MZ signature)
        if plaintext[:2] == b"MZ":
            results.append(("CBC with IV prefix", plaintext))
            return results

        # Try unpadding
        try:
            plaintext_unpadded = unpad(plaintext, AES.block_size)
            if plaintext_unpadded[:2] == b"MZ":
                results.append(("CBC with padding", plaintext_unpadded))
                return results
        except:
            pass

    except Exception as e:
        pass

    # Try AES-CTR
    try:
        if iv is None:
            iv = ciphertext[:16]
            data = ciphertext[16:]
        else:
            data = ciphertext

        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
        plaintext = cipher.decrypt(data)

        if plaintext[:2] == b"MZ":
            results.append(("CTR", plaintext))
            return results
    except:
        pass

    # Try AES-ECB (less likely but possible)
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)

        if plaintext[:2] == b"MZ":
            results.append(("ECB", plaintext))
            return results
    except:
        pass

    return results


def extract_keys_from_binary(exe_path):
    """Extract potential AES keys from the Go binary"""
    with open(exe_path, "rb") as f:
        data = f.read()

    keys = []

    # Common key patterns in CTFs
    # Search for 16-byte or 32-byte aligned strings
    import re

    for key_len in [16, 32]:
        # Look for printable ASCII keys
        pattern = rb"[A-Za-z0-9_\-!@#$%^&*()+=]{" + str(key_len).encode() + rb"}"
        matches = re.finditer(pattern, data)

        for m in matches:
            key = m.group()
            if key not in keys:
                keys.append(key)

    return keys


def main():
    # Read the encrypted file
    with open("dist/ghost", "rb") as f:
        ciphertext = f.read()

    print(f"[*] Ghost file size: {len(ciphertext)} bytes")
    print(f"[*] First 32 bytes (hex): {ciphertext[:32].hex()}")

    # Extract potential keys from the executable
    print("\n[*] Extracting potential keys from c8763.exe...")
    potential_keys = extract_keys_from_binary("dist/c8763.exe")
    print(f"[*] Found {len(potential_keys)} potential keys")

    # Try each key
    for i, key in enumerate(potential_keys[:20]):  # Try first 20
        print(f"\n[{i + 1}] Trying key: {key[:32]}")

        # Ensure key is correct length
        if len(key) == 16 or len(key) == 32:
            results = try_decrypt_aes(ciphertext, key)

            if results:
                mode, plaintext = results[0]
                print(f"[+] SUCCESS with {mode}!")
                print(f"[+] Decrypted size: {len(plaintext)} bytes")
                print(f"[+] Header: {plaintext[:64].hex()}")

                # Save decrypted file
                output = "dist/ghost_decrypted.exe"
                with open(output, "wb") as f:
                    f.write(plaintext)
                print(f"[+] Saved to {output}")

                # Check for flag in strings
                import subprocess

                result = subprocess.run(
                    ["strings", output], capture_output=True, text=True
                )
                if (
                    "CSC{" in result.stdout
                    or "FLAG{" in result.stdout
                    or "flag{" in result.stdout
                ):
                    print("\n[+] FOUND FLAG IN STRINGS:")
                    for line in result.stdout.split("\n"):
                        if "CSC{" in line or "FLAG{" in line or "flag{" in line:
                            print(f"    {line}")

                return

    print("\n[-] No valid decryption found with extracted keys")
    print("[*] Trying common CTF keys...")

    # Common CTF keys
    common_keys = [
        b"0123456789abcdef",
        b"ABCDEFGHIJKLMNOP",
        b"cschahaha1234567",  # Based on the zip password
        b"AbyssPhantonTeam",
        b"ghost1234567890",
    ]

    for key in common_keys:
        # Pad to 16 bytes if needed
        if len(key) < 16:
            key = key + b"\x00" * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]

        print(f"[*] Trying: {key}")
        results = try_decrypt_aes(ciphertext, key)

        if results:
            mode, plaintext = results[0]
            print(f"[+] SUCCESS with {mode}!")
            output = "dist/ghost_decrypted.exe"
            with open(output, "wb") as f:
                f.write(plaintext)
            print(f"[+] Saved to {output}")
            return


if __name__ == "__main__":
    main()
