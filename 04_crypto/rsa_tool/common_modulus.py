#!/usr/bin/env python3
"""
RSA common modulus attack: recover plaintext when same n used with different e.

Vulnerability: Two ciphertexts c1, c2 encrypted with exponents e1, e2 and same n.
Using extended GCD: if gcd(e1, e2) = 1, then a*e1 + b*e2 = 1.
Message: m = c1^a * c2^b (mod n)

Attack requires:
    - Two ciphertexts with same modulus n
    - Different public exponents e1, e2
    - gcd(e1, e2) = 1
    - No padding (raw RSA)

Usage:
    python common_modulus.py -c1 12345 -e1 17 -c2 67890 -e2 19 -n 260753
    python common_modulus.py -c1 c1.txt -e1 17 -c2 c2.txt -e2 19 -n n.txt
"""

import sys
import argparse
from rsa_common import egcd

try:
    from Crypto.PublicKey import RSA

    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False


def load_int_or_file(value):
    """Load integer from argument (int or filename)."""
    try:
        return int(value)
    except:
        try:
            with open(value, "r") as f:
                return int(f.read().strip(), 0)
        except:
            return None


def common_modulus_attack(c1, e1, c2, e2, n):
    """Recover plaintext using common modulus attack.

    Requires: gcd(e1, e2) = 1

    Args:
        c1, c2: ciphertexts
        e1, e2: exponents
        n: shared modulus

    Returns:
        plaintext m if successful, else None
    """
    # Extended GCD to find a, b where a*e1 + b*e2 = gcd(e1, e2)
    g, a, b = egcd(e1, e2)

    if g != 1:
        print(f"[-] gcd({e1}, {e2}) = {g} != 1")
        print("[!] Cannot apply attack (exponents not coprime)")
        return None

    print(f"[+] Found: {a}*{e1} + {b}*{e2} = 1")

    # Calculate m = c1^a * c2^b (mod n)
    # Handle negative exponents
    if a < 0:
        # c1^a = (c1^-1)^(-a) mod n
        c1_inv = pow(c1, -1, n)  # Modular inverse
        m = pow(c1_inv, -a, n)
    else:
        m = pow(c1, a, n)

    if b < 0:
        c2_inv = pow(c2, -1, n)
        m = (m * pow(c2_inv, -b, n)) % n
    else:
        m = (m * pow(c2, b, n)) % n

    return m


def int_to_bytes(num, length=None):
    """Convert integer to bytes."""
    if length is None:
        length = (num.bit_length() + 7) // 8
    if length == 0:
        length = 1
    return num.to_bytes(length, "big")


def main():
    parser = argparse.ArgumentParser(
        description="RSA common modulus attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python common_modulus.py -c1 12345 -e1 17 -c2 67890 -e2 19 -n 260753
  python common_modulus.py -c1 c1.bin -e1 17 -c2 c2.bin -e2 19 -n n.txt
        """,
    )

    parser.add_argument(
        "-c1", "--c1", required=True, help="First ciphertext (int or file)"
    )
    parser.add_argument("-e1", "--e1", type=int, required=True, help="First exponent")
    parser.add_argument(
        "-c2", "--c2", required=True, help="Second ciphertext (int or file)"
    )
    parser.add_argument("-e2", "--e2", type=int, required=True, help="Second exponent")
    parser.add_argument("-n", "--modulus", required=True, help="Modulus (int or file)")
    parser.add_argument("--ascii", action="store_true", help="Output as ASCII")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    # Load parameters
    c1 = load_int_or_file(args.c1)
    c2 = load_int_or_file(args.c2)
    n = load_int_or_file(args.modulus)

    if c1 is None or c2 is None or n is None:
        print("[-] Failed to load parameters")
        sys.exit(1)

    print(f"[*] Common modulus attack")
    print(f"    e1={args.e1}, e2={args.e2}")
    print(f"    n={n}")

    # Run attack
    m = common_modulus_attack(c1, args.e1, c2, args.e2, n)

    if m is not None:
        print(f"[+] SUCCESS! Plaintext: {m}")

        # Try as ASCII
        if args.ascii:
            try:
                plaintext_bytes = int_to_bytes(m)
                plaintext_str = plaintext_bytes.decode("utf-8", errors="replace")
                print(f"[+] As ASCII: {plaintext_str}")
            except:
                pass

        # Output
        if args.output:
            with open(args.output, "w") as f:
                f.write(f"Plaintext (int): {m}\n")
                try:
                    plaintext_bytes = int_to_bytes(m)
                    f.write(f"Plaintext (hex): {plaintext_bytes.hex()}\n")
                    f.write(
                        f"Plaintext (ascii): {plaintext_bytes.decode('utf-8', errors='replace')}\n"
                    )
                except:
                    pass
            print(f"[+] Written to {args.output}")
    else:
        print("[-] Attack failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
