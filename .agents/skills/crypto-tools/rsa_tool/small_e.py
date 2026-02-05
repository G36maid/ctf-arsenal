#!/usr/bin/env python3
"""
RSA small exponent attack: decrypt when e is small (3, 5, 17, etc) and m^e < n.

Vulnerability: If e is small and plaintext is small, then m^e < n means m = cbrt(e).
No modular reduction needed - direct root extraction.

Usage:
    python small_e.py -e 3 -n 221 -c 142
    python small_e.py -e 17 -n modulus -c ciphertext
    python small_e.py --from-file pubkey.pem -c ciphertext

Example:
    RSA: n=221 (15*17), e=3, m=5
    c = m^3 mod n = 125 mod 221 = 125
    Attack: m = cbrt(125) = 5 ✓
"""

import sys
import argparse
from rsa_common import iroot

try:
    from Crypto.PublicKey import RSA

    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False


def small_e_attack(e, n, c):
    """Decrypt RSA ciphertext when m^e < n.

    Args:
        e: public exponent (usually 3, 5, 17)
        n: modulus
        c: ciphertext

    Returns:
        plaintext if found, else None
    """
    # Try direct root extraction
    m = iroot(c, e)

    # Verify: m^e should equal c (if m^e < n)
    if pow(m, e, n) == c:
        return m

    # If not exact, try m+1 in case of rounding
    m_next = m + 1
    if pow(m_next, e, n) == c:
        return m_next

    return None


def attack_from_file(pubkey_path, c):
    """Load RSA public key from PEM file."""
    if not PYCRYPTO_AVAILABLE:
        print("[-] pycryptodome required: pip install pycryptodome")
        return None, None, None

    try:
        key = RSA.import_key(open(pubkey_path).read())
        return key.e, key.n, c
    except Exception as e:
        print(f"[-] Error loading key: {e}")
        return None, None, None


def bytes_to_int(data):
    """Convert bytes to integer."""
    return int.from_bytes(data, "big")


def int_to_bytes(num, length=None):
    """Convert integer to bytes."""
    if length is None:
        length = (num.bit_length() + 7) // 8
    if length == 0:
        length = 1
    return num.to_bytes(length, "big")


def main():
    parser = argparse.ArgumentParser(
        description="RSA small exponent attack (m^e < n)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python small_e.py -e 3 -n 221 -c 125
  python small_e.py -e 3 --from-file pubkey.pem -c ciphertext.bin
  python small_e.py -e 17 -n 560000 -c 123456 --ascii
        """,
    )

    parser.add_argument(
        "-e", "--exponent", type=int, required=True, help="Public exponent"
    )
    parser.add_argument("-n", "--modulus", type=int, help="Modulus")
    parser.add_argument("-c", "--ciphertext", type=int, help="Ciphertext (integer)")
    parser.add_argument("--from-file", help="Load public key from PEM file")
    parser.add_argument("--ascii", action="store_true", help="Output as ASCII string")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    # Load parameters
    if args.from_file:
        e, n, c = attack_from_file(args.from_file, args.ciphertext)
    else:
        e, n, c = args.exponent, args.modulus, args.ciphertext

    if n is None or c is None:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Small exponent attack (e={e}, n={n}, c={c})")

    # Run attack
    m = small_e_attack(e, n, c)

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
        print("[-] Attack failed: m^e >= n (likely)")
        print("[*] Plaintext might be larger. Try common_modulus or other attacks.")
        sys.exit(1)


if __name__ == "__main__":
    main()
