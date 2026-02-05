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
    print("=" * 50)
    print("Ground Truth Bomb - GPIO ONLY")
    print("=" * 50)
    print("\nGPIO Mapping:")
    print("-" * 50)
    print("  Pin 0  -> GPIO 8")
    print("  Pin 1  -> GPIO 9")
    print("  Pin 2  -> GPIO 10")
    print("  Pin 3  -> GPIO 11")
    print("  Pin 4  -> GPIO 12")
    print("  Pin 5  -> GPIO 13")
    print("  Pin 6  -> GPIO 14")
    print("  Pin 7  -> GPIO 15")
    print("  Pin 8  -> GPIO 0 (Right-Top)")
    print("  Pin 9  -> GPIO 22")
    print("  Pin 10 -> GPIO 21")
    print("  Pin 11 -> GPIO 20")
    print("  Pin 12 -> GPIO 19")
    print("  Pin 13 -> GPIO 18")
    print("  Pin 14 -> GPIO 17")
    print("  Pin 15 -> GPIO 16")

    print("\n" + "=" * 50)
    print("ENTER SEED (10 hex characters)")
    print("=" * 50)
    print("Example: deadbeef01, abcdef0123")

    while True:
        try:
            seed = input("\nSeed: ").strip()

            if len(seed) == 0:
                print("\nBye!")
                break

            if len(seed) != 10:
                print("ERROR: Seed must be 10 characters")
                continue

            if not all(c.lower() in "0123456789abcdef" for c in seed):
                print("ERROR: Seed can only contain 0-9 and a-f")
                continue

            print(f"\nSeed: {seed}")
            print("Calculating...\n")

            pins_order = calculate_pins_order(seed)
            check_pins = [8, 9, 10, 11, 12, 13, 14, 15, 0, 22, 21, 20, 19, 18, 17, 16]

            print("=" * 50)
            print("CUTTING ORDER (GPIO ONLY)")
            print("=" * 50)

            for rank in range(1, 17):
                for logical_pin, gpio_pin in enumerate(check_pins):
                    if pins_order[logical_pin] == rank:
                        print(f"  {rank:2d}. GPIO {gpio_pin:2d}")
                        break

            print("\n" + "=" * 50)
            print("INSTRUCTIONS:")
            print("=" * 50)
            print("1. Cut wires in order shown above")
            print("2. Only cut GPIO with current rank = 1")
            print("3. Cutting in wrong order = EXPLOSION")
            print("4. Cutting all correctly = FLAG!")

        except EOFError:
            print("\nBye!")
            break


if __name__ == "__main__":
    main()
