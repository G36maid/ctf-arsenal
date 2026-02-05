#!/usr/bin/env python3
"""
Try common password patterns with the ghost_decrypted.exe binary
Format: ABC0123DEFGHIJK (3 letters, 4 digits, 8 letters)
"""

import subprocess
import string


def try_password(password):
    """Try a password with wine"""
    try:
        proc = subprocess.Popen(
            ["wine", "dist/ghost_decrypted.exe"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        stdout, stderr = proc.communicate(input=password + "\n")

        if "Invalid password" not in stdout:
            return True, stdout
        return False, None
    except Exception as e:
        return False, None


def generate_passwords():
    """Generate password candidates based on constraints"""
    # Based on the constraints, we know:
    # - Length: 15
    # - Format: ABC0123DEFGHIJK
    #   - [0:3]: Uppercase letters
    #   - [3:7]: Digits
    #   - [7:15]: Uppercase letters

    # Try some common patterns first
    common = [
        "CSC2024CSCCSCC",  # Contest name based
        "APT2024APTAPTA",
        "FLAG2024FLAGGG",
        "WIN2024WINWINW",
        "KEY2024KEYKEYK",
    ]

    for pwd in common:
        yield pwd


def main():
    print("[*] Trying common password patterns...")

    for pwd in generate_passwords():
        print(f"[*] Trying: {pwd}")
        success, output = try_password(pwd)

        if success:
            print(f"[+] SUCCESS! Password: {pwd}")
            print(f"[+] Output:\n{output}")
            return pwd

    print("[-] No common passwords worked. Need to solve constraints...")
    return None


if __name__ == "__main__":
    main()
