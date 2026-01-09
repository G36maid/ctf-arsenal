#!/usr/bin/env python3
import hashlib
import sys


def check_password_constraints(password_bytes):
    if len(password_bytes) != 15:
        return False

    total_sum = sum(password_bytes)
    if total_sum != 0x415:
        return False

    xor_result = (
        password_bytes[0] ^ password_bytes[1] ^ password_bytes[2] ^ password_bytes[3]
    )
    if xor_result != 0x61:
        return False

    product = (
        password_bytes[4] * password_bytes[5] * password_bytes[6] * password_bytes[7]
    )
    if product != 0:
        return False

    sum_of_squares = sum(b * b for b in password_bytes[7:15])
    if sum_of_squares % 100 != 0x3D:
        return False

    return True


def extract_encrypted_data():
    with open("dist/ghost_decrypted_correct.exe", "rb") as f:
        data = f.read()

    salt_pos = data.find(b"CSC_KEY_DERIVATION_SALT_2024")
    print(f"Found salt at offset: {hex(salt_pos) if salt_pos != -1 else 'NOT FOUND'}")

    invalid_padding = data.find(b"invalid padding")
    print(f"Found 'invalid padding' at offset: {hex(invalid_padding)}")

    success_msg = data.find(b"Flag decrypted successfully")
    print(f"Found success message at offset: {hex(success_msg)}")

    return None, None


def brute_force_with_constraints(wordlist_path):
    print(f"\n[*] Brute forcing with constraints from: {wordlist_path}")
    print("[*] Looking for 15-byte passwords matching all constraints...")

    try:
        with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
            tested = 0
            matched = 0

            for line in f:
                password = line.rstrip("\n\r")

                if len(password) != 15:
                    continue

                try:
                    password_bytes = password.encode("utf-8")
                    if len(password_bytes) != 15:
                        continue

                    tested += 1
                    if tested % 100000 == 0:
                        print(
                            f"[*] Tested {tested} passwords, found {matched} constraint matches..."
                        )

                    if check_password_constraints(password_bytes):
                        matched += 1
                        print(
                            f"\n[+] FOUND PASSWORD MATCHING ALL CONSTRAINTS: {password!r}"
                        )
                        print(f"    Bytes: {password_bytes.hex()}")
                        return password

                except UnicodeDecodeError:
                    continue

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        return None

    print(
        f"\n[*] Tested {tested} 15-byte passwords, found {matched} constraint matches"
    )
    return None


def generate_candidates():
    import string
    import itertools

    print("\n[*] Generating candidate passwords...")

    printable = string.ascii_letters + string.digits + string.punctuation + " "

    tested = 0
    for pwd_tuple in itertools.product(printable, repeat=15):
        password = "".join(pwd_tuple)
        password_bytes = password.encode("utf-8")

        tested += 1
        if tested % 1000000 == 0:
            print(f"[*] Tested {tested} candidates...")

        if check_password_constraints(password_bytes):
            print(f"\n[+] FOUND: {password!r}")
            return password

    return None


if __name__ == "__main__":
    print("=" * 70)
    print("CTF Password Constraint Brute Force")
    print("=" * 70)

    extract_encrypted_data()

    wordlists = [
        "03_web/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt",
        "03_web/wordlists/common-passwords.txt",
    ]

    for wordlist in wordlists:
        result = brute_force_with_constraints(wordlist)
        if result:
            print(f"\n[+] PASSWORD FOUND: {result}")
            print(
                f"\n[*] Test with: echo '{result}' | wine dist/ghost_decrypted_correct.exe"
            )
            sys.exit(0)

    print("\n[!] No password found in wordlists.")
    print(
        "[*] Password must be exactly 15 bytes with specific mathematical properties."
    )
    print("[*] This may require custom generation or extracting from binary...")
