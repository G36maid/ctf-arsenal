#!/usr/bin/env python3
"""
Complete password constraint solver based on decompiled validatePassword()

Password format: ABC0123DEFGHIJK (15 characters)
- p[0:3]: Uppercase letters (A-Z)
- p[3:7]: Digits (0-9)
- p[7:15]: Uppercase letters (A-Z)
"""

import itertools


def check_constraints(pwd):
    """Check all constraints from validatePassword()"""
    if len(pwd) != 15:
        return False

    p = [ord(c) for c in pwd]

    try:
        # Constraint 1: Length = 15 (already checked)

        # Constraint 2: Sum of all bytes = 0x415 (1045)
        if sum(p) != 0x415:
            return False

        # Constraint 3: p[0] ^ p[1] ^ p[2] ^ p[3] = 0x61
        if (p[0] ^ p[1] ^ p[2] ^ p[3]) != 0x61:
            return False

        # Constraint 4: (p[4] * p[5] * p[6] * p[7]) % 256 = 0
        if ((p[4] * p[5] * p[6] * p[7]) & 0xFF) != 0:
            return False

        # Constraint 5: Sum of squares [7:15] mod 100 = 0x3d (61)
        if sum(p[i] ** 2 for i in range(7, 15)) % 100 != 0x3D:
            return False

        # Constraint 6: XOR of all bytes = 0x49
        xor_all = 0
        for byte in p:
            xor_all ^= byte
        if xor_all != 0x49:
            return False

        # Constraint 7-9: Character ranges
        for i in range(3):
            if not (0x41 <= p[i] <= 0x5A):  # A-Z
                return False

        for i in range(3, 7):
            if not (0x30 <= p[i] <= 0x39):  # 0-9
                return False

        for i in range(7, 15):
            if not (0x41 <= p[i] <= 0x5A):  # A-Z
                return False

        # Constraint 10: p[0] + p[1] + p[2] = 0xd9 (217)
        if p[0] + p[1] + p[2] != 0xD9:
            return False

        # Constraint 11: p[4] + p[3] + p[5] + p[6] = 0xc9 (201)
        if p[4] + p[3] + p[5] + p[6] != 0xC9:
            return False

        # Constraint 12: Sum [7:15] = 0x273 (627)
        if sum(p[7:15]) != 0x273:
            return False

        # Constraint 13: p[2] == p[0]
        if p[2] != p[0]:
            return False

        # Constraint 14: p[5] == p[3]
        if p[5] != p[3]:
            return False

        # Constraint 15: p[10] == p[9]
        if p[10] != p[9]:
            return False

        # Constraint 16: p[0] ^ p[1] ^ p[2] = 0x53
        if (p[0] ^ p[1] ^ p[2]) != 0x53:
            return False

        # Constraint 17: p[4] ^ p[3] ^ p[5] ^ p[6] = 5
        if (p[4] ^ p[3] ^ p[5] ^ p[6]) != 5:
            return False

        # Constraint 18: XOR [8:15] = 0x1f
        xor_8_15 = 0
        for i in range(8, 15):
            xor_8_15 ^= p[i]
        if xor_8_15 != 0x1F:
            return False

        # Constraint 19: (p[5] * p[4] * p[3] * p[6]) % 256 = 0xc0 (192)
        if ((p[5] * p[4] * p[3] * p[6]) & 0xFF) != 0xC0:
            return False

        # Constraint 20: p[7] ^ p[8] = 0x11
        if (p[7] ^ p[8]) != 0x11:
            return False

        # Constraint 21: p[9] * p[7] * p[8] = 0x695f0 (431600)
        if p[9] * p[7] * p[8] != 0x695F0:
            return False

        # Constraint 22: p[11] ^ p[12] = 0x18
        if (p[11] ^ p[12]) != 0x18:
            return False

        # Constraint 23: p[11] > p[12]
        if p[11] <= p[12]:
            return False

        # Constraint 24: p[6] > p[4]
        if p[6] <= p[4]:
            return False

        # Constraint 25: p[13] > p[14]
        if p[13] <= p[14]:
            return False

        # Constraint 26: Sum of cubes [0:7] = 0x19ad5e (1683806)
        if sum(p[i] ** 3 for i in range(7)) != 0x19AD5E:
            return False

        # Constraint 27: Sum of cubes [7:15] = 0x3c3c15 (3947541)
        if sum(p[i] ** 3 for i in range(7, 15)) != 0x3C3C15:
            return False

        # Constraint 28: (p[4] * p[3] * p[2] * p[1] * p[0]) % 1000 = 800
        if (p[4] * p[3] * p[2] * p[1] * p[0]) % 1000 != 800:
            return False

        # Constraint 29: Sum of products p[i]*p[i+1] for i in [7:14] = 0xaa70 (43632)
        sum_products = sum(p[i] * p[i + 1] for i in range(7, 14))
        if sum_products != 0xAA70:
            return False

        # Constraint 30: XOR of even indices [2,4,6,8,10,12,14] = 0x1c
        xor_even = 0
        for i in range(2, 15, 2):
            xor_even ^= p[i]
        if xor_even != 0x1C:
            return False

        # Constraint 31: XOR of odd indices [3,5,7,9,11,13] = 0x55
        xor_odd = 0
        for i in range(3, 14, 2):
            xor_odd ^= p[i]
        if xor_odd != 0x55:
            return False

        # Constraint 32: Sum of squares [0:3] mod 100 = 0x43 (67)
        if sum(p[i] ** 2 for i in range(3)) % 100 != 0x43:
            return False

        # Constraint 33: (p[13] * p[12] * p[11] * p[10]) % 10000 = 0x1dd6 (7638)
        if (p[13] * p[12] * p[11] * p[10]) % 10000 != 0x1DD6:
            return False

        return True

    except Exception as e:
        print(f"Error checking password '{pwd}': {e}")
        return False


def solve_smart():
    """
    Use constraints to narrow down the search space intelligently
    """
    # From constraints: p[0] = p[2], so we have p[0] p[1] p[0]
    # p[0] + p[1] + p[2] = 0xd9 = 217
    # 2*p[0] + p[1] = 217
    # p[0] ^ p[1] ^ p[2] = 0x53 (where p[2] = p[0])
    # p[0] ^ p[1] ^ p[0] = 0x53
    # p[1] = 0x53

    p1 = ord("S")  # 0x53 = 83
    # 2*p[0] + 83 = 217
    # 2*p[0] = 134
    # p[0] = 67 = 'C'

    p0 = ord("C")
    p2 = ord("C")

    print(f"[*] Solved first 3 chars: {chr(p0)}{chr(p1)}{chr(p2)} (CSC)")

    # From p[3] = p[5] and p[4] + p[3] + p[5] + p[6] = 0xc9 = 201
    # p[4] + 2*p[3] + p[6] = 201
    # All are digits (0x30-0x39, i.e., 48-57)

    # From p[4] ^ p[3] ^ p[5] ^ p[6] = 5 (where p[5] = p[3])
    # p[4] ^ p[3] ^ p[3] ^ p[6] = 5
    # p[4] ^ p[6] = 5

    # From (p[5] * p[4] * p[3] * p[6]) % 256 = 0xc0 = 192 (where p[5] = p[3])
    # (p[3]^2 * p[4] * p[6]) % 256 = 192

    # From (p[4] * p[5] * p[6] * p[7]) % 256 = 0 - but p[7] is letter, not digit!
    # Wait, this is wrong. Let me recheck the indices...
    # Actually p[7] is the first uppercase letter after digits

    # Let me check with p[3]=p[5], p[4] + 2*p[3] + p[6] = 201
    # And p[6] > p[4]

    for p3 in range(ord("0"), ord("9") + 1):
        p5 = p3
        for p4 in range(ord("0"), ord("9") + 1):
            for p6 in range(ord("0"), ord("9") + 1):
                if p4 + 2 * p3 + p6 == 201 and p6 > p4:
                    if (p4 ^ p3 ^ p5 ^ p6) == 5:
                        if ((p5 * p4 * p3 * p6) & 0xFF) == 0xC0:
                            print(
                                f"[*] Found digits: {chr(p3)}{chr(p4)}{chr(p5)}{chr(p6)}"
                            )
                            # Now we need the last 8 uppercase letters
                            # This requires solving more complex constraints
                            # Let's try brute force with these first 7 chars fixed
                            prefix = (
                                chr(p0)
                                + chr(p1)
                                + chr(p2)
                                + chr(p3)
                                + chr(p4)
                                + chr(p5)
                                + chr(p6)
                            )
                            print(f"[*] Prefix: {prefix}")
                            return prefix

    return None


def main():
    print("[+] Smart constraint solver for ghost_decrypted.exe password")
    print()

    prefix = solve_smart()
    if prefix:
        print(f"\n[*] Prefix found: {prefix}")
        print(f"[*] Now need to solve for the last 8 uppercase letters...")

        # Try to solve for the last 8 letters
        # This is still complex, but we've reduced the search space significantly
    else:
        print("[-] Could not solve even the prefix!")


if __name__ == "__main__":
    main()
