#!/usr/bin/env python3
"""
Caesar cipher brute-force attack with frequency analysis scoring.

Usage:
    python caesar.py "KHOOR ZRUOG"
    python caesar.py -c "KHOOR ZRUOG" -o output.txt

Output: List of all 26 rotations ranked by English letter frequency score.
"""

import sys
import argparse
from collections import Counter

# English letter frequency (ETAOIN SHRDLU pattern)
ENGLISH_FREQ = {
    "E": 11.1507,
    "A": 8.1672,
    "R": 7.5809,
    "I": 7.0674,
    "O": 7.5809,
    "T": 11.1607,
    "N": 6.7482,
    "S": 6.3327,
    "H": 6.0094,
    "D": 4.2543,
    "L": 4.0365,
    "C": 2.7779,
    "U": 2.7601,
    "M": 2.4152,
    "W": 2.3612,
    "F": 2.2228,
    "G": 2.0820,
    "Y": 1.9740,
    "P": 1.9133,
    "B": 1.4697,
    "V": 0.9769,
    "K": 0.5731,
    "J": 0.1965,
    "X": 0.1508,
    "Q": 0.0995,
    "Z": 0.0772,
}


def clean_text(text):
    """Remove non-alphabetic characters and convert to uppercase."""
    return "".join(c.upper() for c in text if c.isalpha())


def rotate(text, shift):
    """Rotate text by shift positions (Caesar cipher)."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A")
            rotated = chr((ord(char) - base + shift) % 26 + base)
            result.append(rotated)
        else:
            result.append(char)
    return "".join(result)


def score_text(text):
    """Score text based on English letter frequency.
    Higher score = more likely English plaintext.
    """
    text = clean_text(text)
    if not text:
        return 0.0

    counter = Counter(text)
    score = 0.0

    for letter, freq_pct in ENGLISH_FREQ.items():
        observed_count = counter.get(letter, 0)
        observed_pct = (observed_count / len(text)) * 100
        # Chi-squared scoring
        expected = (freq_pct / 100) * len(text)
        if expected > 0:
            score += ((observed_count - expected) ** 2) / expected

    return -score  # Negative because we want to minimize chi-squared


def caesar_attack(ciphertext):
    """Brute force all 26 Caesar rotations and rank by frequency."""
    results = []

    for shift in range(26):
        plaintext = rotate(ciphertext, shift)
        score = score_text(plaintext)
        results.append((shift, plaintext, score))

    # Sort by score (descending)
    results.sort(key=lambda x: x[2], reverse=True)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Caesar cipher brute-force attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python caesar.py "KHOOR ZRUOG"
  python caesar.py -c "KHOOR ZRUOG" -o results.txt
  python caesar.py -c ciphertext.txt | head -5
        """,
    )
    parser.add_argument("ciphertext", nargs="?", help="Ciphertext to decrypt")
    parser.add_argument(
        "-c", "--cipher", dest="cipher_arg", help="Ciphertext (alt. argument)"
    )
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    args = parser.parse_args()

    ciphertext = args.ciphertext or args.cipher_arg

    if not ciphertext:
        parser.print_help()
        sys.exit(1)

    # Run attack
    results = caesar_attack(ciphertext)

    # Format output
    output_lines = []
    output_lines.append("=== Caesar Cipher Attack Results ===\n")

    for shift, plaintext, score in results:
        output_lines.append(f"[ROT {shift:2d}] Score: {score:8.2f}")
        output_lines.append(f"  {plaintext}\n")

    output_text = "\n".join(output_lines)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"[+] Results written to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
