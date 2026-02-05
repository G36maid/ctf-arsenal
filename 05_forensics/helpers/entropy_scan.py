#!/usr/bin/env python3
"""
Entropy Scanner - Detect compression, encryption, randomness levels in files.

Usage:
    python entropy_scan.py <file>

Output:
    Prints entropy value and interpretation (0.0 = repetitive, 8.0 = random)
"""

import sys
import math
from collections import Counter


def calculate_entropy(data):
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    length = len(data)

    # Shannon entropy formula
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def interpret_entropy(entropy):
    """Return interpretation of entropy value."""
    if entropy < 1.0:
        return "Low entropy - highly repetitive data (plaintext, sparse)"
    elif entropy < 3.0:
        return "Medium entropy - some compression/structure"
    elif entropy < 6.0:
        return "High entropy - compressed or slightly encrypted"
    else:
        return "Very high entropy - encrypted, compressed, or random"


def main():
    if len(sys.argv) < 2:
        print("Usage: python entropy_scan.py <file>")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        entropy = calculate_entropy(data)
        interpretation = interpret_entropy(entropy)

        print(f"[*] File: {filepath}")
        print(f"[*] Size: {len(data)} bytes")
        print(f"[*] Entropy: {entropy:.2f} bits/byte")
        print(f"[*] Assessment: {interpretation}")

        # Quick interpretation hints
        if entropy > 7.5:
            print(
                "\n[!] Suggestion: High entropy detected - may be encrypted/compressed"
            )
            print("    - Try decompression (gzip, bzip2, xz)")
            print("    - Check for encryption signatures")
        elif entropy < 2.0:
            print("\n[!] Suggestion: Low entropy - likely plaintext or sparse data")
            print("    - Try strings extraction")
            print("    - Look for embedded files with binwalk")

    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
