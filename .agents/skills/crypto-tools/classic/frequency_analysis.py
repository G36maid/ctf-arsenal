#!/usr/bin/env python3
"""
Frequency analysis for ciphertext.

Usage:
    python frequency_analysis.py "CIPHERTEXT"
    python frequency_analysis.py ciphertext.txt

Displays:
    - Letter frequency distribution (sorted)
    - Comparison with English baseline
    - Entropy calculation
    - Likely cipher type hints
"""

import sys
import argparse
import math
from collections import Counter

# English letter frequency (ETAOIN SHRDLU)
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
    """Extract letters only, convert to uppercase."""
    return "".join(c.upper() for c in text if c.isalpha())


def analyze_frequency(ciphertext):
    """Analyze letter frequencies in ciphertext."""
    ciphertext = clean_text(ciphertext)
    if not ciphertext:
        return None

    counter = Counter(ciphertext)
    total = len(ciphertext)

    # Calculate percentages
    freq = {}
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = counter.get(letter, 0)
        pct = (count / total) * 100
        freq[letter] = pct

    return freq, counter, total


def calculate_entropy(counter, total):
    """Calculate Shannon entropy (0-4.7 bits for letters)."""
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def chi_squared_test(observed_freq, total):
    """Chi-squared test against English frequency."""
    chi2 = 0.0
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        observed = observed_freq[letter] / 100 * total
        expected = ENGLISH_FREQ[letter] / 100 * total
        if expected > 0:
            chi2 += ((observed - expected) ** 2) / expected
    return chi2


def guess_cipher_type(ciphertext, freq):
    """Heuristically guess cipher type."""
    text = clean_text(ciphertext)

    hints = []

    # Check entropy
    counter = Counter(text)
    entropy = calculate_entropy(counter, len(text))

    if entropy < 3.0:
        hints.append("Low entropy → likely simple substitution or weak cipher")
    elif entropy > 4.5:
        hints.append("High entropy → likely strong cipher or random")

    # Check for flat distribution (polyalphabetic)
    chi2 = chi_squared_test(freq, len(text))
    if chi2 < 50:
        hints.append("Flat distribution → likely polyalphabetic (Vigenere, Playfair)")
    elif chi2 > 150:
        hints.append("Peaked distribution → likely monoalphabetic (Caesar, Simple)")

    # Check for most common letter
    most_common = max(freq.items(), key=lambda x: x[1])
    if most_common[1] > 12:
        hints.append(
            f"High single letter frequency ({most_common[0]}: {most_common[1]:.1f}%) → simple substitution likely"
        )

    # All lowercase frequencies
    vowels = sum(freq.get(v, 0) for v in "AEIOU")
    if vowels < 30:
        hints.append("Low vowel frequency → spaces might be encrypted or artificial")

    return hints


def main():
    parser = argparse.ArgumentParser(
        description="Ciphertext frequency analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python frequency_analysis.py "KHOOR ZRUOG"
  python frequency_analysis.py ciphertext.txt
  python frequency_analysis.py -c "CIPHER" --verbose
        """,
    )
    parser.add_argument("ciphertext", nargs="?", help="Ciphertext string or file")
    parser.add_argument(
        "-c", "--cipher", dest="cipher_arg", help="Ciphertext (alternative)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    ciphertext = args.ciphertext or args.cipher_arg

    if not ciphertext:
        parser.print_help()
        sys.exit(1)

    # Load from file if necessary
    if ciphertext and (len(ciphertext) < 100 and ciphertext.lower().endswith(".txt")):
        try:
            with open(ciphertext, "r") as f:
                ciphertext = f.read()
        except:
            pass

    # Analyze
    result = analyze_frequency(ciphertext)
    if not result:
        print("[-] No alphabetic characters found")
        sys.exit(1)

    freq, counter, total = result
    entropy = calculate_entropy(counter, total)
    chi2 = chi_squared_test(freq, total)

    # Build output
    output = []
    output.append("=== Frequency Analysis ===\n")
    output.append(f"Text length: {total} characters")
    output.append(f"Unique letters: {len(counter)}")
    output.append(f"Shannon entropy: {entropy:.2f} bits (max 4.7)")
    output.append(f"Chi-squared vs English: {chi2:.2f}\n")

    # Display frequencies sorted
    output.append("=== Letter Frequencies ===\n")
    output.append("Letter | Cipher% | English% | Diff")
    output.append("-------|---------|----------|-------")

    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    for letter, pct in sorted_freq:
        english_pct = ENGLISH_FREQ[letter]
        diff = pct - english_pct
        marker = (
            "^^" if pct > english_pct + 2 else "vv" if pct < english_pct - 2 else "  "
        )
        output.append(
            f"  {letter}   | {pct:6.2f}% | {english_pct:6.2f}% | {diff:+5.1f}% {marker}"
        )

    # Analysis
    output.append("\n=== Cipher Type Analysis ===\n")
    hints = guess_cipher_type(ciphertext, freq)
    for i, hint in enumerate(hints, 1):
        output.append(f"[{i}] {hint}")

    if args.verbose:
        output.append("\n=== Extended Analysis ===\n")
        output.append(f"Counter distribution: {counter}")
        output.append(f"Top 5 letters: {sorted_freq[:5]}")

        # Digraph analysis (simple)
        text = clean_text(ciphertext)
        digraphs = Counter(text[i : i + 2] for i in range(len(text) - 1))
        output.append(f"\nTop digraphs: {digraphs.most_common(10)}")

    output_text = "\n".join(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"[+] Analysis written to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
