#!/usr/bin/env python3
"""
Password Constraint Solver for ghost_decrypted.exe

Constraints extracted from validatePassword() function:
- Password length: 15 characters
- Format: ABC0123DEFGHIJK
  - [0:3]: Uppercase letters (A-Z)
  - [3:7]: Digits (0-9)
  - [7:15]: Uppercase letters (A-Z)
"""

from z3 import *


def solve_password():
    # Create 15 byte variables (password is 15 characters)
    p = [BitVec(f"p{i}", 8) for i in range(15)]

    solver = Solver()

    # === Constraint 1: Password length is 15 ===
    # (already enforced by array size)

    # === Constraint 2: Sum of all bytes = 0x415 (1045) ===
    sum_all = Sum([ZeroExt(24, p[i]) for i in range(15)])
    solver.add(sum_all == 0x415)

    # === Constraint 3: p[0] ^ p[1] ^ p[2] ^ p[3] = 0x61 ('a') ===
    solver.add(p[0] ^ p[1] ^ p[2] ^ p[3] == 0x61)

    # === Constraint 4: p[4] * p[5] * p[6] * p[7] = 0 (mod 256) ===
    # This means at least one of p[4:8] must be 0 or multiple gives 0 mod 256
    # But they are digits (0x30-0x39), so product mod 256 must be 0
    # Only way: product is divisible by 256
    product_4567 = (
        ZeroExt(24, p[4]) * ZeroExt(24, p[5]) * ZeroExt(24, p[6]) * ZeroExt(24, p[7])
    )
    solver.add((product_4567 & 0xFF) == 0)

    # === Constraint 5: Sum of squares [7:15] mod 100 = 0x3d (61) ===
    sum_squares_7_15 = Sum(
        [ZeroExt(24, p[i]) * ZeroExt(24, p[i]) for i in range(7, 15)]
    )
    solver.add(sum_squares_7_15 % 100 == 0x3D)

    # === Constraint 6: XOR of all bytes = 0x49 ('I') ===
    xor_all = p[0]
    for i in range(1, 15):
        xor_all = xor_all ^ p[i]
    solver.add(xor_all == 0x49)

    # === Constraint 7: [0:3] are uppercase letters (A-Z) ===
    for i in range(3):
        solver.add(p[i] >= 0x41)  # 'A'
        solver.add(p[i] <= 0x5A)  # 'Z'

    # === Constraint 8: [3:7] are digits (0-9) ===
    for i in range(3, 7):
        solver.add(p[i] >= 0x30)  # '0'
        solver.add(p[i] <= 0x39)  # '9'

    # === Constraint 9: [7:15] are uppercase letters (A-Z) ===
    for i in range(7, 15):
        solver.add(p[i] >= 0x41)  # 'A'
        solver.add(p[i] <= 0x5A)  # 'Z'

    # === Constraint 10: p[0] + p[1] + p[2] = 0xd9 (217) ===
    solver.add(ZeroExt(24, p[0]) + ZeroExt(24, p[1]) + ZeroExt(24, p[2]) == 0xD9)

    # === Constraint 11: p[4] + p[3] + p[5] + p[6] = 0xc9 (201) ===
    solver.add(
        ZeroExt(24, p[4]) + ZeroExt(24, p[3]) + ZeroExt(24, p[5]) + ZeroExt(24, p[6])
        == 0xC9
    )

    # === Constraint 12: Sum [7:15] = 0x273 (627) ===
    sum_7_15 = Sum([ZeroExt(24, p[i]) for i in range(7, 15)])
    solver.add(sum_7_15 == 0x273)

    # === Constraint 13: p[2] == p[0] ===
    solver.add(p[2] == p[0])

    # === Constraint 14: p[5] == p[3] ===
    solver.add(p[5] == p[3])

    # === Constraint 15: p[10] == p[9] ===
    solver.add(p[10] == p[9])

    # === Constraint 16: p[0] ^ p[1] ^ p[2] = 0x53 ('S') ===
    solver.add(p[0] ^ p[1] ^ p[2] == 0x53)

    # === Constraint 17: p[4] ^ p[3] ^ p[5] ^ p[6] = 5 ===
    solver.add(p[4] ^ p[3] ^ p[5] ^ p[6] == 5)

    # === Constraint 18: XOR of [8:15] = 0x1f (31) ===
    xor_8_15 = p[8]
    for i in range(9, 15):
        xor_8_15 = xor_8_15 ^ p[i]
    solver.add(xor_8_15 == 0x1F)

    # === Constraint 19: (p[5] * p[4] * p[3] * p[6]) % 256 = 0xc0 (192) ===
    product_5436 = (
        ZeroExt(24, p[5]) * ZeroExt(24, p[4]) * ZeroExt(24, p[3]) * ZeroExt(24, p[6])
    )
    solver.add((product_5436 & 0xFF) == 0xC0)

    # === Constraint 20: p[7] ^ p[8] = 0x11 (17) ===
    solver.add(p[7] ^ p[8] == 0x11)

    # === Constraint 21: p[9] * p[7] * p[8] = 0x695f0 (431600) ===
    solver.add(ZeroExt(24, p[9]) * ZeroExt(24, p[7]) * ZeroExt(24, p[8]) == 0x695F0)

    # === Constraint 22: p[11] ^ p[12] = 0x18 (24) ===
    solver.add(p[11] ^ p[12] == 0x18)

    # === Constraint 23: p[11] > p[12] ===
    solver.add(UGT(p[11], p[12]))

    # === Constraint 24: p[6] > p[4] ===
    solver.add(UGT(p[6], p[4]))

    # === Constraint 25: p[13] > p[14] ===
    solver.add(UGT(p[13], p[14]))

    # === Constraint 26: Sum of cubes [0:7] = 0x19ad5e (1683806) ===
    sum_cubes_0_7 = Sum(
        [ZeroExt(24, p[i]) * ZeroExt(24, p[i]) * ZeroExt(24, p[i]) for i in range(7)]
    )
    solver.add(sum_cubes_0_7 == 0x19AD5E)

    # === Constraint 27: Sum of cubes [7:15] = 0x3c3c15 (3947541) ===
    sum_cubes_7_15 = Sum(
        [
            ZeroExt(24, p[i]) * ZeroExt(24, p[i]) * ZeroExt(24, p[i])
            for i in range(7, 15)
        ]
    )
    solver.add(sum_cubes_7_15 == 0x3C3C15)

    # === Constraint 28: (p[4] * p[3] * p[2] * p[1] * p[0]) % 1000 = 800 ===
    product_43210 = (
        ZeroExt(24, p[4])
        * ZeroExt(24, p[3])
        * ZeroExt(24, p[2])
        * ZeroExt(24, p[1])
        * ZeroExt(24, p[0])
    )
    solver.add(product_43210 % 1000 == 800)

    print("[*] Solving constraints...")
    if solver.check() == sat:
        model = solver.model()
        password = "".join([chr(model[p[i]].as_long()) for i in range(15)])
        print(f"[+] Password found: {password}")

        # Verify constraints
        print("\n[*] Verifying constraints:")
        bytes_list = [ord(c) for c in password]
        print(f"    Password bytes: {bytes_list}")
        print(f"    Sum of all: {sum(bytes_list)} (expected: {0x415})")
        print(
            f"    XOR of all: {bytes_list[0] ^ bytes_list[1] ^ bytes_list[2] ^ bytes_list[3] ^ bytes_list[4] ^ bytes_list[5] ^ bytes_list[6] ^ bytes_list[7] ^ bytes_list[8] ^ bytes_list[9] ^ bytes_list[10] ^ bytes_list[11] ^ bytes_list[12] ^ bytes_list[13] ^ bytes_list[14]} (expected: {0x49})"
        )

        return password
    else:
        print("[-] No solution found!")
        return None


if __name__ == "__main__":
    password = solve_password()
    if password:
        print(f"\n[+] Use this password: {password}")
