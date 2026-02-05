#!/usr/bin/env python3
import itertools


def check_all_constraints(pwd):
    if len(pwd) != 15:
        return False

    p = [ord(c) for c in pwd]

    # Check all constraints
    if sum(p) != 0x415:  # 1045
        return False

    if sum(p[7:15]) != 0x273:  # 627
        return False

    xor_all = 0
    for byte in p:
        xor_all ^= byte
    if xor_all != 0x49:
        return False

    if sum(p[i] ** 2 for i in range(7, 15)) % 100 != 0x3D:  # 61
        return False

    if p[11] ^ p[12] != 0x18:
        return False

    if p[11] <= p[12]:
        return False

    if p[13] <= p[14]:
        return False

    if sum(p[i] ** 3 for i in range(7, 15)) != 0x3C3C15:  # 3947541
        return False

    if sum(p[i] * p[i + 1] for i in range(7, 14)) != 0xAA70:  # 43632
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

    if (p[13] * p[12] * p[11] * p[10]) % 10000 != 0x1DD6:  # 7638
        return False

    return True


prefix = "CSC2025PASS"
target_sum = 316

print(f"[*] Brute-forcing last 4 characters...")
print(f"[*] Prefix: {prefix}")
print(f"[*] Need 4 uppercase letters summing to {target_sum}")
print()

letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Narrow down: we need letters summing to 316
# Average = 79 = 'O'
# Try combinations around this average

count = 0
for combo in itertools.combinations_with_replacement(letters, 4):
    for perm in set(itertools.permutations(combo)):
        suffix = "".join(perm)
        p_suffix = [ord(c) for c in suffix]

        if sum(p_suffix) != target_sum:
            continue

        # Check p[11] > p[12] and p[13] > p[14]
        if p_suffix[0] <= p_suffix[1]:
            continue
        if p_suffix[2] <= p_suffix[3]:
            continue

        # Check p[11] ^ p[12] = 0x18
        if p_suffix[0] ^ p_suffix[1] != 0x18:
            continue

        pwd = prefix + suffix
        count += 1
        if count % 1000 == 0:
            print(f"[*] Tested {count} combinations...")

        if check_all_constraints(pwd):
            print(f"\n[+] FOUND: {pwd}")
            break

print(f"\n[-] Tested {count} combinations, no solution found")
