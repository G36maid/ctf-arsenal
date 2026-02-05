#!/usr/bin/env python3
"""
RSA Wiener attack: recover private exponent from large d (when d < n^0.25).

Vulnerability: When RSA is generated with weak random, private exponent d can be
too large. Wiener's attack uses continued fractions to find d/n approximation.

Attack requires:
    - d < n^0.25 (roughly)
    - Public exponent e and modulus n
    - No padding (textbook RSA)

Time: O(log^2 n) - very fast even for large n.

Usage:
    python wiener.py -e 65537 -n modulus
    python wiener.py --from-file pubkey.pem

References:
    Wiener, M. J. (1990). "Cryptanalysis of Short Secret Exponents"
"""

import sys
import argparse
from rsa_common import gcd

try:
    from Crypto.PublicKey import RSA

    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False


def continued_fraction(e, n):
    """Compute continued fraction expansion of e/n.

    Returns: list of convergents [(num1, den1), (num2, den2), ...]
    """
    convergents = []

    k = e
    d = n

    a_i = k // d
    convergents.append((a_i, 1))

    while d != 0:
        k = k - a_i * d
        if k == 0:
            break

        # Swap
        k, d = d, k
        a_i = k // d

        # Calculate convergent
        if len(convergents) == 1:
            num = a_i * convergents[0][0] + 1
            den = a_i
        else:
            num = a_i * convergents[-1][0] + convergents[-2][0]
            den = a_i * convergents[-1][1] + convergents[-2][1]

        convergents.append((num, den))

    return convergents


def check_d(e, d, n):
    """Verify if (e, d, n) form valid RSA pair.

    Check if e*d ≡ 1 (mod φ(n)) by finding p, q factors.
    """
    # ed ≡ 1 (mod φ(n))
    # ed - 1 = k*φ(n) for some k
    # ed - 1 = k*(n - p - q + 1)

    # Try to factor n using d
    # If ed ≡ 1 (mod φ(n)), then there exists k such that ed = 1 + k*φ(n)
    # We can try different k values to find factors

    for k in range(1, e):
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # n - phi = p + q - 1
        s = n - phi + 1

        # Solve: p + q = s, p*q = n
        # p, q = (s ± √(s² - 4n)) / 2

        delta = s * s - 4 * n
        if delta < 0:
            continue

        sqrt_delta = int(delta**0.5)
        if sqrt_delta * sqrt_delta != delta:
            continue

        p = (s + sqrt_delta) // 2
        q = (s - sqrt_delta) // 2

        if p * q == n and p > 1 and q > 1:
            print(f"[+] Found factors: p={p}, q={q}")
            return True

    return False


def wiener_attack(e, n):
    """Apply Wiener's attack to recover d.

    Returns: (d, p, q) if successful, else (None, None, None)
    """
    print(f"[*] Computing continued fraction convergents...")
    convergents = continued_fraction(e, n)

    print(f"[*] Checking {len(convergents)} convergents...")

    for i, (k, d) in enumerate(convergents):
        if d == 0:
            continue

        if gcd(k, d) != 1:
            continue

        # Simplify fraction k/d (not critical but helps)
        g = gcd(k, d)
        k //= g
        d //= g

        # Check if this (e, d) pair works
        if check_d(e, d, n):
            return d

    return None


def load_key_from_pem(path):
    """Load public key from PEM file."""
    if not PYCRYPTO_AVAILABLE:
        print("[-] pycryptodome required for PEM loading")
        return None, None

    try:
        key = RSA.import_key(open(path).read())
        return key.e, key.n
    except:
        return None, None


def main():
    parser = argparse.ArgumentParser(
        description="RSA Wiener attack (d < n^0.25)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wiener.py -e 65537 -n 1234567890
  python wiener.py --from-file pubkey.pem
  python wiener.py -e 17 -n 3233

Vulnerability: d < n^0.25 (roughly d < 2^(keysize/4))
Typical: 1024-bit RSA needs d < 256 bits to be vulnerable
        """,
    )

    parser.add_argument("-e", "--exponent", type=int, help="Public exponent")
    parser.add_argument("-n", "--modulus", type=int, help="Modulus")
    parser.add_argument("--from-file", help="Load from PEM file")

    args = parser.parse_args()

    if args.from_file:
        e, n = load_key_from_pem(args.from_file)
        if e is None:
            print("[-] Failed to load key")
            sys.exit(1)
    else:
        e = args.exponent
        n = args.modulus

    if e is None or n is None:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Wiener Attack")
    print(f"    e={e}")
    print(f"    n={n} ({n.bit_length()} bits)")
    print(f"    Vulnerable if d < {int(n**0.25)} (approximately n^0.25)")

    # Run attack
    d = wiener_attack(e, n)

    if d:
        print(f"\n[+] SUCCESS! Private exponent d = {d}")
        print(f"[+] Can now decrypt any ciphertext: m = c^{d} mod {n}")
    else:
        print(f"\n[-] Attack failed: likely d >= n^0.25 (not vulnerable)")
        print("[*] Try other attacks (common modulus, small e, factorization)")
        sys.exit(1)


if __name__ == "__main__":
    main()
