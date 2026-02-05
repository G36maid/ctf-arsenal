#!/usr/bin/env python3
"""
Single-byte XOR attack: brute force all 256 keys with frequency scoring.

Usage:
    python xor_single_byte.py "48656c6c6f"
    python xor_single_byte.py -c "48656c6c6f" --hex
    python xor_single_byte.py ciphertext.bin

Input: hex-encoded or binary string
Output: All 256 XOR keys ranked by English frequency score
"""

import sys
import argparse
from collections import Counter
import binascii

# English letter frequency
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


def hex_to_bytes(hex_string):
    """Convert hex string to bytes."""
    hex_string = hex_string.replace(" ", "").replace("\n", "")
    try:
        return binascii.unhexlify(hex_string)
    except:
        return None


def bytes_to_hex(data):
    """Convert bytes to hex string."""
    return binascii.hexlify(data).decode()


def xor_bytes(data, key):
    """XOR bytes with single-byte key."""
    return bytes(b ^ key for b in data)


def score_text(plaintext):
    """Score plaintext based on English letter frequency.
    Only counts alphabetic characters.
    """
    # Extract letters
    letters = "".join(
        c.upper() for c in plaintext.decode("utf-8", errors="replace") if c.isalpha()
    )

    if not letters:
        return -1000.0  # Non-text: very low score

    counter = Counter(letters)
    score = 0.0

    for letter, freq_pct in ENGLISH_FREQ.items():
        observed_count = counter.get(letter, 0)
        expected = (freq_pct / 100) * len(letters)
        if expected > 0:
            score += ((observed_count - expected) ** 2) / expected

    return -score  # Negative chi-squared


def xor_single_byte_attack(ciphertext):
    """Try all 256 XOR keys and rank by frequency."""
    results = []

    for key in range(256):
        plaintext = xor_bytes(ciphertext, key)
        score = score_text(plaintext)

        try:
            plaintext_str = plaintext.decode("utf-8", errors="replace")
        except:
            plaintext_str = plaintext.decode("latin-1", errors="replace")

        results.append((key, plaintext_str, plaintext, score))

    # Sort by score (highest = best)
    results.sort(key=lambda x: x[3], reverse=True)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Single-byte XOR brute force",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xor_single_byte.py "48656c6c6f"
  python xor_single_byte.py -c "48656c6c6f" --top 10
  python xor_single_byte.py ciphertext.bin --binary
  python xor_single_byte.py -c "48656c6c6f" -o results.txt
        """,
    )
    parser.add_argument("ciphertext", nargs="?", help="Hex-encoded ciphertext")
    parser.add_argument(
        "-c", "--cipher", dest="cipher_arg", help="Ciphertext (alternative)"
    )
    parser.add_argument(
        "-b", "--binary", action="store_true", help="Binary input (not hex)"
    )
    parser.add_argument("--top", type=int, default=20, help="Show top N results")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    ciphertext_input = args.ciphertext or args.cipher_arg

    if not ciphertext_input:
        parser.print_help()
        sys.exit(1)

    # Load ciphertext
    if args.binary or (ciphertext_input and ciphertext_input.lower().endswith(".bin")):
        # Binary input
        try:
            with open(ciphertext_input, "rb") as f:
                ciphertext = f.read()
        except:
            try:
                ciphertext = ciphertext_input.encode()
            except:
                print("[-] Cannot read binary file")
                sys.exit(1)
    else:
        # Hex input
        if ciphertext_input.lower().endswith(
            ".hex"
        ) or ciphertext_input.lower().endswith(".txt"):
            try:
                with open(ciphertext_input, "r") as f:
                    ciphertext_input = f.read().strip()
            except:
                pass

        ciphertext = hex_to_bytes(ciphertext_input)
        if not ciphertext:
            print("[-] Invalid hex string")
            sys.exit(1)

    # Run attack
    print(f"[*] Attacking {len(ciphertext)} bytes with {256} keys...")
    results = xor_single_byte_attack(ciphertext)

    # Format output
    output = []
    output.append("=== Single-Byte XOR Attack Results ===\n")
    output.append(
        f"Ciphertext: {bytes_to_hex(ciphertext[:32])}{'...' if len(ciphertext) > 32 else ''}\n"
    )

    output.append(f"Top {min(args.top, len(results))} results:\n")
    output.append("Key | Hex | Score | Plaintext")
    output.append("----|-----|-------|----------")

    for i, (key, plaintext_str, plaintext_bytes, score) in enumerate(
        results[: args.top]
    ):
        # Truncate plaintext for display
        display = plaintext_str[:60].replace("\n", "\\n").replace("\x00", "\\x00")
        if len(plaintext_str) > 60:
            display += "..."

        output.append(f" {key:3d} | 0x{key:02x} | {score:6.2f} | {display}")

    output_text = "\n".join(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"[+] Results written to {args.output}")
    else:
        print(output_text)

    # Print best key
    if results:
        best_key = results[0][0]
        best_text = results[0][1]
        print(f"\n[+] Best guess (key=0x{best_key:02x}):")
        print(f"    {best_text[:100]}{'...' if len(best_text) > 100 else ''}")


if __name__ == "__main__":
    main()
