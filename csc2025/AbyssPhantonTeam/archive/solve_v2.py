#!/usr/bin/env python3


def solve():
    print("Solving password...")
    print("Format: AAA0000BBBBBBBB (3 uppercase, 4 digits, 8 uppercase)")
    print()

    for c0 in range(ord("A"), ord("Z") + 1):
        for c1 in range(ord("A"), ord("Z") + 1):
            c2 = c0

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
                    for d3 in range(ord("0"), ord("9") + 1):
                        if d0 + d1 + d2 + d3 != 201:
                            continue

                        if (d2 ^ d0 ^ d1 ^ d3) != 5:
                            continue

                        if (d1 * d2 * d3) % 256 != 0:
                            continue

                        if (d1 * d2 * d3 * 0) % 256 != 0xC0:
                            continue

                        for c3 in range(ord("A"), ord("Z") + 1):
                            for c4 in range(ord("A"), ord("Z") + 1):
                                if (c3 ^ c4) != 0x11:
                                    continue

                                c5 = c4

                                if c5 * c3 * c4 != 0x695F0:
                                    continue

                                for c6 in range(ord("A"), ord("Z") + 1):
                                    for c7 in range(ord("A"), ord("Z") + 1):
                                        if c3 + c4 + c5 + c6 + c7 != 627:
                                            continue

                                        xor_check = c3
                                        for x in [c4, c5, c6, c7]:
                                            xor_check ^= x

                                        if xor_check != 0x1F:
                                            continue

                                        sum_sq = (
                                            c3 * c3
                                            + c4 * c4
                                            + c5 * c5
                                            + c6 * c6
                                            + c7 * c7
                                        )
                                        if sum_sq % 100 != 61:
                                            continue

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

                                        total = sum(pwd)
                                        if total != 1045:
                                            continue

                                        xor_all = 0
                                        for b in pwd:
                                            xor_all ^= b
                                        if xor_all != 0x49:
                                            continue

                                        pwd_str = pwd.decode("ascii")
                                        print(f"FOUND: {pwd_str}")
                                        return pwd_str

    print("No password found")
    return None


if __name__ == "__main__":
    result = solve()
    if result:
        print(f'\nTest: echo "{result}" | wine dist/ghost_decrypted_correct.exe')
