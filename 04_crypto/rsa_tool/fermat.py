#!/usr/bin/env python3
"""
RSA Fermat factorization: factor n when p and q are close (difference small).

Vulnerability: When p ≈ q (close factors), Fermat factorization is fast.
Searches for n = a² - b² = (a-b)(a+b), where a-b=p and a+b=q.

Algorithm:
    1. Start with a = ceil(√n)
    2. Compute b² = a² - n
    3. If b² is perfect square, found factors: p = a-b, q = a+b
    4. Increment a and repeat

Time: O(n^0.25) iterations in worst case, but often much faster.
Fast when |p - q| is small: ~(p-q)² iterations.

Usage:
    python fermat.py -n modulus
    python fermat.py -n 3233
    python fermat.py --from-file pubkey.pem

Example:
    n = 3233 = 53 × 61 (close factors, distance = 8)
    Fast factorization in ~4 iterations
"""

import sys
import argparse
import math
from rsa_common import isqrt

try:
    from Crypto.PublicKey import RSA

    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False


def fermat_factor(n, max_iterations=1000000):
    """Fermat factorization: factor n = p*q where p ≈ q.

    Args:
        n: number to factor (must be odd)
        max_iterations: limit iterations to prevent infinite loops

    Returns:
        (p, q) if factored, else (None, None)
    """
    if n % 2 == 0:
        return 2, n // 2

    # Start with a = ceil(√n)
    a = isqrt(n)
    if a * a < n:
        a += 1

    b2 = a * a - n

    iterations = 0
    while iterations < max_iterations:
        b = isqrt(b2)

        # Check if b² = b2 (perfect square)
        if b * b == b2:
            p = a - b
            q = a + b

            if p > 1 and q > 1 and p * q == n:
                return p, q

        a += 1
        b2 += 2 * a - 1  # Optimization: (a+1)² - n = a² - n + 2a + 1
        iterations += 1

    return None, None


def load_key_from_pem(path):
    """Load public key from PEM file."""
    if not PYCRYPTO_AVAILABLE:
        print("[-] pycryptodome required for PEM loading")
        return None

    try:
        key = RSA.import_key(open(path).read())
        return key.n
    except:
        return None


def euler_phi(p, q):
    """Calculate Euler's totient: φ(n) = (p-1)(q-1)."""
    return (p - 1) * (q - 1)


def compute_private_exponent(e, phi):
    """Compute d such that e*d ≡ 1 (mod φ)."""
    from rsa_common import invmod

    try:
        return invmod(e, phi)
    except:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="RSA Fermat factorization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fermat.py -n 3233
  python fermat.py -n 1234567890
  python fermat.py --from-file pubkey.pem
  python fermat.py -n 3233 -e 65537  # Also compute private exponent

Vulnerability: Fast when p and q are close
    - 512-bit RSA: factors found in seconds if |p-q| < 2^256
    - 1024-bit RSA: needs |p-q| < 2^512 (very unlikely)
        """,
    )

    parser.add_argument("-n", "--modulus", type=int, help="Modulus to factor")
    parser.add_argument(
        "-e", "--exponent", type=int, help="Public exponent (to compute d)"
    )
    parser.add_argument("--from-file", help="Load from PEM file")
    parser.add_argument(
        "--max-iterations", type=int, default=1000000, help="Max iterations"
    )

    args = parser.parse_args()

    if args.from_file:
        n = load_key_from_pem(args.from_file)
        e = None
        if n is None:
            print("[-] Failed to load key")
            sys.exit(1)
    else:
        n = args.modulus
        e = args.exponent

    if n is None:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Fermat Factorization")
    print(f"    n={n} ({n.bit_length()} bits)")
    print(f"    Estimated a: {isqrt(n)} to {isqrt(n) + 1000}")

    # Run attack
    p, q = fermat_factor(n, args.max_iterations)

    if p and q:
        print(f"\n[+] SUCCESS! Factorization: n = {p} × {q}")

        if e:
            phi = euler_phi(p, q)
            d = compute_private_exponent(e, phi)
            if d:
                print(f"[+] Public exponent: e={e}")
                print(f"[+] Private exponent: d={d}")
                print(f"[+] φ(n) = {phi}")
            else:
                print("[-] Could not compute d (e not coprime to φ)")

        print(f"\n[+] Can now decrypt any ciphertext")
    else:
        print(f"\n[-] Factorization failed")
        print(f"[!] Likely |p - q| is large (not vulnerable to Fermat)")
        print(f"[*] Try: FactorDB, RsaCtfTool, or general factorization")
        sys.exit(1)


if __name__ == "__main__":
    main()
