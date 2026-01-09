#!/usr/bin/env python3
import sys


def check_all_constraints(p):
    if len(p) != 15:
        return False, "len"

    if sum(p) != 1045:
        return False, "sum"

    bVar9 = p[1] ^ p[0] ^ p[2]
    if (p[3] ^ bVar9) != 0x61:
        return False, "xor1"

    if ((p[4] * p[5] * p[6] * p[7]) & 0xFF) != 0:
        return False, "prod1"

    sum_sq = sum(p[i] * p[i] for i in range(7, 15))
    if sum_sq % 100 != 0x3D:
        return False, "sq"

    xor_all = 0
    for b in p:
        xor_all ^= b
    if xor_all != 0x49:
        return False, "xorall"

    if bVar9 != 0x53:
        return False, "bvar9"

    for i in range(3):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"upper{i}"

    for i in range(3, 7):
        if not (0x30 <= p[i] <= 0x39):
            return False, f"digit{i}"

    for i in range(7, 15):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"upper{i}"

    if sum(p[7:15]) != 0x273:
        return False, "sum715"

    if p[0] + p[1] + p[2] != 0xD9:
        return False, "sum012"

    if p[3] + p[4] + p[5] + p[6] != 0xC9:
        return False, "sum3456"

    if p[2] != p[0]:
        return False, "p2p0"

    if p[5] != p[3]:
        return False, "p5p3"

    if p[10] != p[9]:
        return False, "p10p9"

    if (p[4] ^ p[3] ^ p[5] ^ p[6]) != 5:
        return False, "xor3456"

    xor_7_14 = p[7]
    for i in range(8, 15):
        xor_7_14 ^= p[i]
    if xor_7_14 != 0x1F:
        return False, "xor714"

    if ((p[5] * p[4] * p[3] * p[6]) % 0x100) != 0xC0:
        return False, "prodmod"

    if (p[7] ^ p[8]) != 0x11:
        return False, "xor78"

    if (p[9] * p[7] * p[8]) != 0x695F0:
        return False, "prod789"

    if (p[11] ^ p[12]) != 0x18:
        return False, "xor1112"

    if p[11] <= p[12]:
        return False, "p11p12"

    if p[6] <= p[4]:
        return False, "p6p4"

    if p[13] <= p[14]:
        return False, "p13p14"

    sum_cubes_06 = sum(p[i] ** 3 for i in range(7))
    if sum_cubes_06 != 0x19AD5E:
        return False, "cubes06"

    sum_cubes_714 = sum(p[i] ** 3 for i in range(7, 15))
    if sum_cubes_714 != 0x3C3C15:
        return False, "cubes714"

    if ((p[0] * p[1] * p[2] * p[3] * p[4]) % 1000) != 800:
        return False, "prodmod1000"

    sum_products = sum(p[i + 1] * p[i] for i in range(7, 14))
    if sum_products != 0xAA70:
        return False, "sumprod"

    return True, "OK"


print("[*] Brute forcing password with ALL constraints...")
print("[*] This may take several minutes...")
print()

tested = 0

for c0 in range(ord("A"), ord("Z") + 1):
    c2 = c0
    for c1 in range(ord("A"), ord("Z") + 1):
        if c0 + c1 + c2 != 217:
            continue

        bVar9 = c1 ^ c0 ^ c2
        if bVar9 != 0x53:
            continue

        for d0 in range(ord("0"), ord("9") + 1):
            if (d0 ^ bVar9) != 0x61:
                continue

            d1 = d0

            for d2 in range(ord("0"), ord("9") + 1):
                if d2 <= d0:
                    continue

                for d3 in range(ord("0"), ord("9") + 1):
                    if d0 + d1 + d2 + d3 != 201:
                        continue

                    if (d0 ^ d1 ^ d2 ^ d3) != 5:
                        continue

                    if ((d1 * d2 * d3 * d0) % 256) != 192:
                        continue

                    if ((c0 * c1 * c2 * d0 * d1) % 1000) != 800:
                        continue

                    sum_cubes = c0**3 + c1**3 + c2**3 + d0**3 + d1**3 + d2**3 + d3**3
                    if sum_cubes != 0x19AD5E:
                        continue

                    tested += 1
                    pwd_first = [c0, c1, c2, d0, d1, d2, d3]
                    print(
                        f"[+] Found valid first 7: {''.join(chr(x) for x in pwd_first)}"
                    )

                    for c3 in range(ord("A"), ord("Z") + 1):
                        for c4 in range(ord("A"), ord("Z") + 1):
                            if (c3 ^ c4) != 0x11:
                                continue

                            for c5 in range(ord("A"), ord("Z") + 1):
                                if (c5 * c3 * c4) != 0x695F0:
                                    continue

                                c6 = c5

                                for c7 in range(ord("A"), ord("Z") + 1):
                                    for c8 in range(ord("A"), ord("Z") + 1):
                                        for c9 in range(ord("A"), ord("Z") + 1):
                                            for c10 in range(ord("A"), ord("Z") + 1):
                                                pwd = pwd_first + [
                                                    c3,
                                                    c4,
                                                    c5,
                                                    c6,
                                                    c7,
                                                    c8,
                                                    c9,
                                                    c10,
                                                ]

                                                valid, msg = check_all_constraints(pwd)
                                                if valid:
                                                    pwd_str = "".join(
                                                        chr(x) for x in pwd
                                                    )
                                                    print(f"\n{'=' * 70}")
                                                    print(
                                                        f"[+] FOUND VALID PASSWORD: {pwd_str}"
                                                    )
                                                    print(f"{'=' * 70}")
                                                    sys.exit(0)

print(f"\n[!] No password found after {tested} partial matches")
