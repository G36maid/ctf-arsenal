#!/usr/bin/env python3
"""
Complete password validation constraints from main::main_validatePassword

Password format: 15 bytes
Pattern: [3 uppercase letters][4 digits][8 uppercase letters]
Example: ABC1234DEFGHIJK
"""


def check_all_constraints(pwd):
    if isinstance(pwd, str):
        pwd = pwd.encode("utf-8")

    if len(pwd) != 15:
        return False, f"Length must be 15, got {len(pwd)}"

    p = pwd

    total_sum = sum(p)
    if total_sum != 0x415:
        return False, f"Sum != 1045, got {total_sum}"

    xor_0123 = p[0] ^ p[1] ^ p[2] ^ p[3]
    if xor_0123 != 0x61:
        return False, f"XOR(0:4) != 0x61, got {hex(xor_0123)}"

    prod_4567 = p[4] * p[5] * p[6] * p[7]
    if prod_4567 != 0:
        return False, f"Product(4:8) != 0"

    sum_sq_7_15 = sum(b * b for b in p[7:15])
    if sum_sq_7_15 % 100 != 0x3D:
        return False, f"Sum of squares % 100 != 61, got {sum_sq_7_15 % 100}"

    xor_all = 0
    for b in p:
        xor_all ^= b
    if xor_all != 0x49:
        return False, f"XOR(all) != 0x49, got {hex(xor_all)}"

    sum_7_15 = sum(p[7:15])
    if sum_7_15 != 0x273:
        return False, f"Sum(7:15) != 0x273 (627), got {sum_7_15}"

    for i in range(3):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"p[{i}] not uppercase, got {chr(p[i])}"

    for i in range(3, 7):
        if not (0x30 <= p[i] <= 0x39):
            return False, f"p[{i}] not digit, got {chr(p[i])}"

    for i in range(7, 15):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"p[{i}] not uppercase, got {chr(p[i])}"

    if p[0] + p[1] + p[2] != 0xD9:
        return False, f"Sum(0:3) != 0xd9 (217), got {p[0] + p[1] + p[2]}"

    if p[4] + p[5] + p[6] + p[3] != 0xC9:
        return False, f"Sum(3:7) != 0xc9 (201), got {sum(p[3:7])}"

    if p[2] != p[0]:
        return False, f"p[2] != p[0], got {chr(p[2])} != {chr(p[0])}"

    if p[5] != p[3]:
        return False, f"p[5] != p[3], got {chr(p[5])} != {chr(p[3])}"

    if p[10] != p[9]:
        return False, f"p[10] != p[9], got {chr(p[10])} != {chr(p[9])}"

    xor_result = p[0] ^ p[1] ^ p[2] ^ p[3]
    if xor_result != 0x53:
        return False, f"XOR(special) != 0x53, got {hex(xor_result)}"

    xor_4567_check = p[4] ^ p[3] ^ p[5] ^ p[6]
    if xor_4567_check != 5:
        return False, f"XOR(3:7) != 5, got {xor_4567_check}"

    xor_8_to_14 = p[7]
    for i in range(8, 15):
        xor_8_to_14 ^= p[i]
    if xor_8_to_14 != 0x1F:
        return False, f"XOR(7:15) != 0x1f, got {hex(xor_8_to_14)}"

    prod_mod = (p[5] * p[4] * p[3] * p[6]) % 0x100
    if prod_mod != 0xC0:
        return False, f"Product mod 256 != 0xc0, got {hex(prod_mod)}"

    if (p[7] ^ p[8]) != 0x11:
        return False, f"XOR(7,8) != 0x11, got {hex(p[7] ^ p[8])}"

    prod_789 = p[9] * p[7] * p[8]
    if prod_789 != 0x695F0:
        return False, f"Product(7,8,9) != 0x695f0, got {hex(prod_789)}"

    return True, "ALL CONSTRAINTS SATISFIED!"


def solve_password():
    print("Solving password with constraints...")
    print("\nKnown structure: [3 uppercase][4 digits][8 uppercase]")
    print("Example format: ABC1234DEFGHIJK\n")

    print("Key constraints:")
    print("- p[0] = p[2] (first and third letter same)")
    print("- p[3] = p[5] (first and third digit same)")
    print("- p[9] = p[10] (two consecutive uppercase same)")
    print("- Sum of first 3 letters = 217 (0xd9)")
    print("- Sum of 4 digits = 201 (0xc9)")
    print("- Sum of last 8 letters = 627 (0x273)")
    print()

    tested = 0

    for c0 in range(ord("A"), ord("Z") + 1):
        for c1 in range(ord("A"), ord("Z") + 1):
            c2 = c0

            if c0 + c1 + c2 != 0xD9:
                continue

            for d0 in range(ord("0"), ord("9") + 1):
                d1 = d0

                for d2 in range(ord("0"), ord("9") + 1):
                    for d3 in range(ord("0"), ord("9") + 1):
                        if d0 + d1 + d2 + d3 != 0xC9:
                            continue

                        if (d1 ^ d0 ^ d2 ^ d3) != 5:
                            continue

                        if (d2 * d1 * d0 * d3) % 0x100 != 0xC0:
                            continue

                        for c3 in range(ord("A"), ord("Z") + 1):
                            for c4 in range(ord("A"), ord("Z") + 1):
                                if (c3 ^ c4) != 0x11:
                                    continue

                                for c5 in range(ord("A"), ord("Z") + 1):
                                    if c5 != c4:
                                        continue

                                    if c5 * c3 * c4 != 0x695F0:
                                        continue

                                    for c6 in range(ord("A"), ord("Z") + 1):
                                        for c7 in range(ord("A"), ord("Z") + 1):
                                            tested += 1
                                            if tested % 100000 == 0:
                                                print(
                                                    f"Tested {tested} combinations..."
                                                )

                                            pwd = bytes(
                                                [
                                                    c0,
                                                    c1,
                                                    c2,
                                                    d0,
                                                    d1,
                                                    d2,
                                                    d3,
                                                    c3,
                                                    c4,
                                                    c5,
                                                    c6,
                                                    c7,
                                                ]
                                            )

                                            valid, msg = check_all_constraints(pwd)
                                            if valid:
                                                pwd_str = pwd.decode("ascii")
                                                print(f"\n{'=' * 60}")
                                                print(f"FOUND PASSWORD: {pwd_str}")
                                                print(f"{'=' * 60}\n")
                                                return pwd_str

    print(f"\nTested {tested} combinations, no match found")
    return None


if __name__ == "__main__":
    print("=" * 70)
    print("CTF Password Constraint Solver - Complete Edition")
    print("=" * 70)
    print()

    result = solve_password()

    if result:
        print(f"\nTest with:")
        print(f'  echo "{result}" | wine dist/ghost_decrypted_correct.exe')
    else:
        print("\nNo password found. Check constraints...")
