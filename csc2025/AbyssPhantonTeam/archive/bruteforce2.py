#!/usr/bin/env python3


def check_constraints(pwd):
    p = [ord(c) for c in pwd]

    if sum(p) != 0x415:
        return False
    if sum(p[7:15]) != 0x273:
        return False

    xor_all = 0
    for byte in p:
        xor_all ^= byte
    if xor_all != 0x49:
        return False

    if sum(p[i] ** 2 for i in range(7, 15)) % 100 != 0x3D:
        return False
    if sum(p[i] ** 3 for i in range(7, 15)) != 0x3C3C15:
        return False
    if sum(p[i] * p[i + 1] for i in range(7, 14)) != 0xAA70:
        return False

    xor_8_15 = 0
    for i in range(8, 15):
        xor_8_15 ^= p[i]
    if xor_8_15 != 0x1F:
        return False

    xor_odd = 0
    for i in range(3, 14, 2):
        xor_odd ^= p[i]
    if xor_odd != 0x55:
        return False

    if (p[13] * p[12] * p[11] * p[10]) % 10000 != 0x1DD6:
        return False

    return True


prefix = "CSC2025PASS"
target_sum = 316

p11_p12_pairs = [
    ("P", "H"),
    ("Q", "I"),
    ("R", "J"),
    ("S", "K"),
    ("T", "L"),
    ("U", "M"),
    ("V", "N"),
    ("W", "O"),
    ("Y", "A"),
    ("Z", "B"),
]

print(f"[*] Brute-forcing with valid p[11], p[12] pairs...")

count = 0
for p11, p12 in p11_p12_pairs:
    pair_sum = ord(p11) + ord(p12)
    remaining = target_sum - pair_sum

    for c13 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for c14 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if ord(c13) <= ord(c14):
                continue

            if ord(c13) + ord(c14) != remaining:
                continue

            pwd = prefix + p11 + p12 + c13 + c14
            count += 1

            if check_constraints(pwd):
                print(f"\n[+] PASSWORD FOUND: {pwd}")
                print(f"[*] Tested {count} combinations")
                exit(0)

print(f"\n[-] No solution found after {count} combinations")
