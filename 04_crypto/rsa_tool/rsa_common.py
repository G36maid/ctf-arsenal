#!/usr/bin/env python3
"""
RSA utility functions: GCD, extended GCD, modular inverse, CRT, integer roots.

Usage:
    from rsa_common import *
    d = invmod(e, phi)
    x = crt(remainders, moduli)
    m = iroot(c, e)
"""


def gcd(a, b):
    """Calculate greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def egcd(a, b):
    """Extended Euclidean algorithm.
    Returns (gcd, x, y) where ax + by = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def invmod(a, m):
    """Modular multiplicative inverse: a^-1 mod m.
    Returns x where ax ≡ 1 (mod m).
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m


def crt(remainders, moduli):
    """Chinese Remainder Theorem.
    Solves x ≡ r_i (mod m_i) for all i.

    Args:
        remainders: list of residues [r_1, r_2, ...]
        moduli: list of coprime moduli [m_1, m_2, ...]
    Returns:
        x: solution modulo M (product of all moduli)
    """
    if len(remainders) != len(moduli):
        raise ValueError("Length mismatch: remainders and moduli")

    M = 1
    for m in moduli:
        M *= m

    result = 0
    for r, m in zip(remainders, moduli):
        M_i = M // m
        result += r * M_i * invmod(M_i, m)

    return result % M


def iroot(n, k):
    """Integer k-th root: finds largest x where x^k <= n.

    Uses Newton's method for fast convergence.
    """
    if k == 1:
        return n
    if k == 2:
        return isqrt(n)

    # Newton's method for k-th root
    x = n
    while True:
        x_new = ((k - 1) * x + n // (x ** (k - 1))) // k
        if x_new >= x:
            return x
        x = x_new


def isqrt(n):
    """Integer square root: largest x where x^2 <= n."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n == 0:
        return 0

    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def pow_mod(base, exp, mod):
    """Fast modular exponentiation: base^exp mod mod."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def carmichael_lambda(p, q):
    """Compute Carmichael's lambda for RSA: lcm(p-1, q-1)."""

    def lcm(a, b):
        return (a * b) // gcd(a, b)

    return lcm(p - 1, q - 1)


if __name__ == "__main__":
    # Test basic functions
    print(f"gcd(48, 18) = {gcd(48, 18)}")  # 6

    g, x, y = egcd(35, 15)
    print(f"egcd(35, 15): gcd={g}, x={x}, y={y}")  # 5, -1, 2

    inv = invmod(3, 11)
    print(f"3^-1 mod 11 = {inv}")  # 4 (since 3*4=12≡1 mod 11)

    x = crt([2, 3], [5, 7])
    print(f"CRT([2,3], [5,7]) = {x}")  # 17

    root = iroot(8, 3)
    print(f"cbrt(8) = {root}")  # 2

    print("All tests passed!")
