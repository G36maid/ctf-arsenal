#!/usr/bin/env python3
import sys


def validate_password(pwd):
    if len(pwd) != 15:
        return False, f"len={len(pwd)}"

    p = [c for c in pwd]

    if sum(p) != 1045:
        return False, f"sum={sum(p)}"

    bVar9 = p[1] ^ p[0] ^ p[2]
    if (p[3] ^ bVar9) != 0x61:
        return False, "xor fail"

    if ((p[4] * p[5] * p[6] * p[7]) & 0xFF) != 0:
        return False, f"prod={p[4] * p[5] * p[6] * p[7] & 0xFF}"

    sum_sq = sum(p[i] * p[i] for i in range(7, 15))
    if sum_sq % 100 != 0x3D:
        return False, f"sq%100={sum_sq % 100}"

    xor_all = 0
    for b in p:
        xor_all ^= b
    if xor_all != 0x49:
        return False, f"xor_all={hex(xor_all)}"

    for i in range(3):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"p[{i}] not upper"

    for i in range(3, 7):
        if not (0x30 <= p[i] <= 0x39):
            return False, f"p[{i}] not digit"

    for i in range(7, 15):
        if not (0x41 <= p[i] <= 0x5A):
            return False, f"p[{i}] not upper"

    sum_7_15 = sum(p[7:15])
    if sum_7_15 != 0x273:
        return False, f"sum_7_15={sum_7_15}"

    if p[0] + p[1] + p[2] != 0xD9:
        return False, "sum_0_2"

    if p[3] + p[4] + p[5] + p[6] != 0xC9:
        return False, "sum_3_6"

    if p[2] != p[0]:
        return False, "p[2]!=p[0]"

    if p[5] != p[3]:
        return False, "p[5]!=p[3]"

    if p[10] != p[9]:
        return False, "p[10]!=p[9]"

    if bVar9 != 0x53:
        return False, "bVar9"

    if (p[4] ^ p[3] ^ p[5] ^ p[6]) != 5:
        return False, "xor_3_6"

    xor_7_14 = p[7]
    for i in range(8, 15):
        xor_7_14 ^= p[i]
    if xor_7_14 != 0x1F:
        return False, "xor_7_14"

    if ((p[5] * p[4] * p[3] * p[6]) % 0x100) != 0xC0:
        return False, f"prod_mod={(p[5] * p[4] * p[3] * p[6]) % 0x100}"

    if (p[7] ^ p[8]) != 0x11:
        return False, "xor_7_8"

    if (p[9] * p[7] * p[8]) != 0x695F0:
        return False, f"prod_789={p[9] * p[7] * p[8]}"

    if (p[11] ^ p[12]) != 0x18:
        return False, "xor_11_12"

    if p[11] <= p[12]:
        return False, "p[11]<=p[12]"

    if p[6] <= p[4]:
        return False, "p[6]<=p[4]"

    return True, "OK"


def solve():
    print("[*] Solving password constraints...")
    print("[*] Format: AAA####BBBBBBBB")
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

                        if (d2 ^ d0 ^ d1 ^ d3) != 5:
                            continue

                        if ((d1 * d2 * d3 * d0) % 256) != 192:
                            continue

                        tested += 1
                        if tested % 1000 == 0:
                            print(f"[*] Tested {tested} combinations...")

                        pwd_partial = [c0, c1, c2, d0, d1, d2, d3]
                        print(
                            f"[+] Found valid first 7 bytes: {''.join(chr(x) for x in pwd_partial)}"
                        )

                        for c3 in range(ord("A"), ord("Z") + 1):
                            for c4 in range(ord("A"), ord("Z") + 1):
                                if (c3 ^ c4) != 0x11:
                                    continue

                                for c5 in range(ord("A"), ord("Z") + 1):
                                    if (c5 * c3 * c4) != 0x695F0:
                                        continue

                                    for c6 in range(ord("A"), ord("Z") + 1):
                                        c7 = c6

                                        if c3 + c4 + c5 + c6 + c7 != 627:
                                            continue

                                        pwd = pwd_partial + [c3, c4, c5, c6, c7]

                                        valid, msg = validate_password(pwd)
                                        if valid:
                                            pwd_str = "".join(chr(x) for x in pwd)
                                            print(f"\n{'=' * 70}")
                                            print(f"[+] FOUND PASSWORD: {pwd_str}")
                                            print(f"{'=' * 70}")
                                            return pwd_str

    print(f"[!] No password found after testing {tested} combinations")
    return None


if __name__ == "__main__":
    result = solve()
    if result:
        print(f"\n[*] Test command:")
        print(f'    echo "{result}" | wine dist/ghost_decrypted_correct.exe')
        sys.exit(0)
    else:
        sys.exit(1)
