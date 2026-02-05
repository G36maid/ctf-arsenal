#!/usr/bin/env python3
import hashlib


def sha512_double(data):
    first = hashlib.sha512(data).digest()
    second = hashlib.sha512(first).digest()
    return second


def calculate_pins_order(seed_string):
    seed_bytes = seed_string.encode("ascii")
    hash_result = sha512_double(seed_bytes)

    pins_order = [0] * 16

    for j in range(64):
        for i in range(8):
            if (hash_result[j] >> i) & 1:
                idx = (j * 8 + i) % 16
                pins_order[idx] += 1

    pairs = []
    for i in range(16):
        pairs.append({"original_index": pins_order[i], "value": i})

    for j1 in range(15):
        for i4 in range(15 - j1):
            if pairs[i4]["original_index"] < pairs[i4 + 1]["original_index"] or (
                pairs[i4]["original_index"] == pairs[i4 + 1]["original_index"]
                and pairs[i4 + 1]["value"] < pairs[i4]["value"]
            ):
                temp_orig = pairs[i4 + 1]["original_index"]
                temp_val = pairs[i4 + 1]["value"]
                pairs[i4 + 1]["original_index"] = pairs[i4]["original_index"]
                pairs[i4 + 1]["value"] = pairs[i4]["value"]
                pairs[i4]["original_index"] = temp_orig
                pairs[i4]["value"] = temp_val

    ranks = [0] * 16
    for i5 in range(16):
        ranks[pairs[i5]["value"]] = i5 + 1

    pins_order = ranks

    return pins_order


def main():
    check_pins = [8, 9, 10, 11, 12, 13, 14, 15, 0, 22, 21, 20, 19, 18, 17, 16]

    print("=" * 60)
    print("Ground Truth Bomb Defuse Guide")
    print("=" * 60)

    print("\nPin Mapping (Logical Pin -> Physical GPIO):")
    print("-" * 60)
    for logical_pin, gpio_pin in enumerate(check_pins):
        pos = "LEFT-TOP" if gpio_pin == 8 else "RIGHT-TOP" if gpio_pin == 0 else ""
        print(f"  Logical Pin {logical_pin:2d} -> GPIO {gpio_pin:2d}  {pos}")

    print("\n" + "=" * 60)
    print("Cutting Order Calculator")
    print("=" * 60)

    print("\nTo calculate the cutting order, provide the seed.")
    print("The seed is a 10-character hex string from EEPROM addresses 2-6")
    print("You can see it on the device display as 'S/N: xxxxx...'")

    while True:
        seed = input("\nEnter seed (10 hex chars, or 'quit'): ").strip()

        if seed.lower() == "quit":
            break

        if len(seed) != 10 or not all(c.lower() in "0123456789abcdef" for c in seed):
            print("Invalid seed! Must be 10 hex characters (0-9, a-f)")
            continue

        pins_order = calculate_pins_order(seed)

        print(f"\nSeed: {seed}")
        print("\nCutting Sequence:")
        print("-" * 60)
        print(f"{'Step':<6} {'Rank':<6} {'Logical':<8} {'GPIO Pin':<10} {'Position'}")
        print("-" * 60)

        for rank in range(1, 17):
            for logical_pin, gpio_pin in enumerate(check_pins):
                if pins_order[logical_pin] == rank:
                    pos = ""
                    if gpio_pin == 8:
                        pos = "(LEFT-TOP)"
                    elif gpio_pin == 0:
                        pos = "(RIGHT-TOP)"

                    print(f"{rank:<6} {rank:<6} {logical_pin:<8} {gpio_pin:<10} {pos}")
                    break

        print("\n" + "=" * 60)
        print("Summary:")
        print("-" * 60)
        print("Cut the wires in the order shown above.")
        print("After each cut, the remaining pins' ranks decrease by 1.")
        print("Cut correctly to see the flag!")
        print("=" * 60)


if __name__ == "__main__":
    main()
