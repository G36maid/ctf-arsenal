#!/usr/bin/env python3
"""
Vigenere cipher attack: key length detection via Kasiski examination + frequency analysis.

Usage:
    python vigenere.py -c "CIPHERTEXT" -w wordlist.txt
    python vigenere.py -c "CIPHERTEXT" --max-keylen 16
    python vigenere.py -c ciphertext.txt -p "known plaintext"

Attacks:
    1. Kasiski examination: find repeating sequences to estimate key length
    2. Wordlist attack: try common words as keys
    3. Frequency analysis: treat each key position as Caesar cipher
"""

import sys
import argparse
from collections import defaultdict, Counter
import re

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


def clean_text(text):
    """Remove non-alphabetic characters, convert to uppercase."""
    return "".join(c.upper() for c in text if c.isalpha())


def gcd(a, b):
    """Greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def gcd_list(lst):
    """GCD of list of numbers."""
    from functools import reduce

    return reduce(gcd, lst)


def kasiski_examination(ciphertext, min_repeat=3):
    """Find repeating sequences to estimate key length.

    Returns sorted list of divisors of GCD of all repeat distances.
    """
    ciphertext = clean_text(ciphertext)
    repeats = defaultdict(list)

    # Find repeating substrings (length 3+)
    for length in range(min_repeat, min(len(ciphertext) // 2, 8)):
        for i in range(len(ciphertext) - length):
            substring = ciphertext[i : i + length]
            for j in range(i + length, len(ciphertext) - length):
                if ciphertext[j : j + length] == substring:
                    distance = j - i
                    repeats[distance].append((substring, i, j))

    if not repeats:
        return list(range(2, 17))  # Default key length range

    # Get GCD of all distances
    distances = list(repeats.keys())
    common_gcd = gcd_list(distances)

    # Find divisors of GCD
    divisors = []
    for i in range(1, int(common_gcd**0.5) + 1):
        if common_gcd % i == 0:
            divisors.append(i)
            if i != common_gcd // i:
                divisors.append(common_gcd // i)

    return sorted(divisors)


def decrypt_vigenere(ciphertext, key):
    """Decrypt Vigenere cipher given key."""
    ciphertext = clean_text(ciphertext)
    key = clean_text(key).upper()
    plaintext = []

    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")
            decrypted = chr((ord(char) - ord("A") - shift) % 26 + ord("A"))
            plaintext.append(decrypted)
            key_index += 1
        else:
            plaintext.append(char)

    return "".join(plaintext)


def score_text(text):
    """Score text based on English frequency."""
    text = clean_text(text)
    if not text:
        return 0.0

    counter = Counter(text)
    score = 0.0

    for letter, freq_pct in ENGLISH_FREQ.items():
        observed_count = counter.get(letter, 0)
        expected = (freq_pct / 100) * len(text)
        if expected > 0:
            score += ((observed_count - expected) ** 2) / expected

    return -score


def frequency_analysis_attack(ciphertext, key_length):
    """Use frequency analysis to recover key of given length."""
    ciphertext = clean_text(ciphertext)
    key = []

    for pos in range(key_length):
        # Extract every key_length-th character starting at pos
        column = ciphertext[pos::key_length]

        # Try all 26 shifts
        best_shift = 0
        best_score = float("-inf")

        for shift in range(26):
            decrypted = "".join(
                chr((ord(c) - ord("A") - shift) % 26 + ord("A")) for c in column
            )
            score = score_text(decrypted)

            if score > best_score:
                best_score = score
                best_shift = shift

        key.append(chr(best_shift + ord("A")))

    return "".join(key)


def wordlist_attack(ciphertext, wordlist_path, max_attempts=1000):
    """Try words from wordlist as Vigenere keys."""
    ciphertext = clean_text(ciphertext)
    results = []

    try:
        with open(wordlist_path, "r") as f:
            for i, line in enumerate(f):
                if i >= max_attempts:
                    break

                key = clean_text(line.strip())
                if not key or len(key) > 20:
                    continue

                plaintext = decrypt_vigenere(ciphertext, key)
                score = score_text(plaintext)
                results.append((key, plaintext, score))

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        return []

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:20]  # Top 20


def main():
    parser = argparse.ArgumentParser(
        description="Vigenere cipher attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vigenere.py -c "CIPHERTEXT" --freq
  python vigenere.py -c "CIPHERTEXT" -w common_words.txt
  python vigenere.py -c ciphertext.txt --max-keylen 10
        """,
    )
    parser.add_argument(
        "-c", "--cipher", required=True, help="Ciphertext file or string"
    )
    parser.add_argument("-w", "--wordlist", help="Wordlist for key guessing")
    parser.add_argument("--freq", action="store_true", help="Use frequency analysis")
    parser.add_argument(
        "--max-keylen", type=int, default=10, help="Max key length to try"
    )
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    # Load ciphertext
    if args.cipher.lower().endswith(".txt") and len(args.cipher) < 100:
        try:
            with open(args.cipher, "r") as f:
                ciphertext = f.read()
        except:
            ciphertext = args.cipher
    else:
        ciphertext = args.cipher

    output = []
    output.append("=== Vigenere Cipher Attack ===\n")

    # Step 1: Kasiski examination
    output.append("[*] Running Kasiski examination...")
    key_lengths = kasiski_examination(ciphertext)
    output.append(f"[+] Probable key lengths: {key_lengths[:10]}\n")

    results = []

    # Step 2: Wordlist attack (if provided)
    if args.wordlist:
        output.append(f"[*] Wordlist attack: {args.wordlist}")
        word_results = wordlist_attack(ciphertext, args.wordlist)
        results.extend(word_results)
        output.append(f"[+] Found {len(word_results)} candidates\n")

    # Step 3: Frequency analysis for top key lengths
    if args.freq or not args.wordlist:
        output.append("[*] Frequency analysis attack...")
        for key_len in key_lengths[: min(5, args.max_keylen)]:
            key = frequency_analysis_attack(ciphertext, key_len)
            plaintext = decrypt_vigenere(ciphertext, key)
            score = score_text(plaintext)
            results.append((key, plaintext, score))
            output.append(f"    Key length {key_len}: {key}")
        output.append("")

    # Sort and display
    results.sort(key=lambda x: x[2], reverse=True)

    output.append("\n=== Top Results ===\n")
    for i, (key, plaintext, score) in enumerate(results[:10]):
        output.append(f"[{i + 1}] Key: {key} | Score: {score:.2f}")
        output.append(f"    {plaintext[:100]}{'...' if len(plaintext) > 100 else ''}\n")

    output_text = "\n".join(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"[+] Results written to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
