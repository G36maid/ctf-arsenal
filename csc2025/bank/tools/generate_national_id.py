#!/usr/bin/env python3
"""
Taiwan National ID generator with checksum calculation
Format: 1 letter + 1 sex digit (1-2) + 7 digits + 1 checksum
"""

LETTER_CHECKSUMS = [
    1,
    0,
    9,
    8,
    7,
    6,
    5,
    4,
    9,
    3,
    2,
    2,
    1,
    0,
    8,
    9,
    8,
    7,
    6,
    5,
    4,
    3,
    1,
    3,
    2,
    0,
]


def generate_national_id(letter_idx, sex, counter):
    """Generate a valid Taiwan National ID with checksum"""
    letter = chr(ord("A") + letter_idx)
    checksum = LETTER_CHECKSUMS[letter_idx]
    sex_digit = sex
    checksum += 8 * sex_digit

    digits = []
    temp = counter
    for i in range(7):
        digit = temp % 10
        temp //= 10
        digits.append(digit)

    digits.reverse()

    for i, digit in enumerate(digits):
        checksum += digit * (7 - i)

    check_digit = (10 - checksum % 10) % 10

    national_id = f"{letter}{sex_digit}{''.join(map(str, digits))}{check_digit}"
    return national_id


def generate_all_ids():
    """Generate all valid Taiwan National IDs"""
    for letter_idx in range(26):
        for sex in [1, 2]:
            for counter in range(10000000):
                yield generate_national_id(letter_idx, sex, counter)


if __name__ == "__main__":
    print("[*] Testing generator...")
    for i, nid in enumerate(generate_all_ids()):
        print(nid)
        if i >= 20:
            break
    print("[*] Generator works!")
