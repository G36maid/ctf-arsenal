#!/usr/bin/env python3
"""
Repeating-key XOR attack: estimate key length via Hamming distance, then solve.

Usage:
    python xor_repeating_key.py "48656c6c6f"
    python xor_repeating_key.py -c "48656c6c6f" -k 4
    python xor_repeating_key.py ciphertext.hex --max-keylen 32

Attack:
    1. Try key lengths 1-32 (or custom range)
    2. For each length, calculate normalized Hamming distance
    3. Lowest Hamming distance = likely key length
    4. Solve as single-byte XOR for each key position
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


def hamming_distance(a, b):
    """Calculate Hamming distance between two bytes."""
    return bin(a ^ b).count("1")


def normalized_hamming_distance(ciphertext, key_length):
    """Calculate average normalized Hamming distance for key length.

    Compare first two blocks, normalized by key length.
    """
    if len(ciphertext) < 2 * key_length:
        return float("inf")

    block1 = ciphertext[:key_length]
    block2 = ciphertext[key_length : 2 * key_length]

    distance = sum(hamming_distance(block1[i], block2[i]) for i in range(key_length))
    return distance / key_length


def score_text(plaintext):
    """Score plaintext based on English letter frequency."""
    letters = "".join(
        c.upper() for c in plaintext.decode("utf-8", errors="replace") if c.isalpha()
    )

    if not letters:
        return -1000.0

    counter = Counter(letters)
    score = 0.0

    for letter, freq_pct in ENGLISH_FREQ.items():
        observed_count = counter.get(letter, 0)
        expected = (freq_pct / 100) * len(letters)
        if expected > 0:
            score += ((observed_count - expected) ** 2) / expected

    return -score


def xor_bytes(data, key):
    """XOR bytes with repeating key."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def single_byte_xor_attack(column):
    """Try all 256 keys for a single column, return best key."""
    best_key = 0
    best_score = float("-inf")

    for key in range(256):
        plaintext = bytes(b ^ key for b in column)
        score = score_text(plaintext)

        if score > best_score:
            best_score = score
            best_key = key

    return best_key


def break_repeating_xor(ciphertext, key_length):
    """Recover key of given length using single-byte XOR attacks."""
    key = []

    for pos in range(key_length):
        # Extract column: every key_length-th byte starting at pos
        column = bytes(ciphertext[i] for i in range(pos, len(ciphertext), key_length))

        # Solve as single-byte XOR
        key_byte = single_byte_xor_attack(column)
        key.append(key_byte)

    return bytes(key)


def main():
    parser = argparse.ArgumentParser(
        description="Repeating-key XOR attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xor_repeating_key.py "48656c6c6f"
  python xor_repeating_key.py -c "48656c6c6f" -k 4
  python xor_repeating_key.py -c "48656c6c6f" --max-keylen 16
  python xor_repeating_key.py ciphertext.hex --top-keylen 5
        """,
    )
    parser.add_argument("ciphertext", nargs="?", help="Hex-encoded ciphertext")
    parser.add_argument(
        "-c", "--cipher", dest="cipher_arg", help="Ciphertext (alternative)"
    )
    parser.add_argument(
        "-k", "--keylen", type=int, help="Known key length (skip detection)"
    )
    parser.add_argument(
        "--max-keylen", type=int, default=32, help="Max key length to try"
    )
    parser.add_argument(
        "--top-keylen", type=int, default=5, help="Try top N key length guesses"
    )
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    ciphertext_input = args.ciphertext or args.cipher_arg

    if not ciphertext_input:
        parser.print_help()
        sys.exit(1)

    # Load ciphertext
    if ciphertext_input.lower().endswith(".hex"):
        try:
            with open(ciphertext_input, "r") as f:
                ciphertext_input = f.read().strip()
        except:
            pass

    ciphertext = hex_to_bytes(ciphertext_input)
    if not ciphertext:
        print("[-] Invalid hex string")
        sys.exit(1)

    output = []
    output.append("=== Repeating-Key XOR Attack ===\n")
    output.append(
        f"Ciphertext: {bytes_to_hex(ciphertext[:32])}{'...' if len(ciphertext) > 32 else ''}\n"
    )

    # Key length detection
    if args.keylen:
        key_lengths = [args.keylen]
    else:
        print(f"[*] Detecting key length (1-{args.max_keylen})...")
        scores = []
        for keylen in range(1, min(args.max_keylen + 1, len(ciphertext) // 2)):
            dist = normalized_hamming_distance(ciphertext, keylen)
            scores.append((keylen, dist))

        scores.sort(key=lambda x: x[1])
        key_lengths = [scores[i][0] for i in range(min(args.top_keylen, len(scores)))]

        output.append("Key length candidates (by Hamming distance):")
        for keylen, dist in scores[:10]:
            output.append(f"  Length {keylen:2d}: {dist:.3f}")
        output.append("")

    # Break for each candidate key length
    results = []
    for key_length in key_lengths:
        print(f"[*] Testing key length {key_length}...")
        key = break_repeating_xor(ciphertext, key_length)
        plaintext = xor_bytes(ciphertext, key)
        score = score_text(plaintext)

        try:
            plaintext_str = plaintext.decode("utf-8", errors="replace")
        except:
            plaintext_str = plaintext.decode("latin-1", errors="replace")

        results.append((key, plaintext_str, score, key_length))

    # Sort by score
    results.sort(key=lambda x: x[2], reverse=True)

    # Display
    output.append("=== Results ===\n")
    for i, (key, plaintext_str, score, keylen) in enumerate(results[:5]):
        output.append(f"[{i + 1}] Key length: {keylen} | Score: {score:.2f}")
        output.append(f"    Key (hex): {bytes_to_hex(key)}")
        output.append(f"    Key (ascii): {key.decode('ascii', errors='replace')}")

        display = plaintext_str[:80].replace("\n", "\\n").replace("\x00", "\\x00")
        if len(plaintext_str) > 80:
            display += "..."
        output.append(f"    Plaintext: {display}\n")

    output_text = "\n".join(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"[+] Results written to {args.output}")
    else:
        print(output_text)

    if results:
        best_key = results[0][0]
        print(f"\n[+] Best key: {bytes_to_hex(best_key)}")
        print(f"    ASCII: {best_key.decode('ascii', errors='replace')}")


if __name__ == "__main__":
    main()
