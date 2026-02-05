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


def generate_cutting_sequence(seed_string):
    check_pins = [8, 9, 10, 11, 12, 13, 14, 15, 0, 22, 21, 20, 19, 18, 17, 16]
    pins_order = calculate_pins_order(seed_string)

    sequence = []
    for rank in range(1, 17):
        for logical_pin, gpio_pin in enumerate(check_pins):
            if pins_order[logical_pin] == rank:
                sequence.append({"step": rank, "gpio_pin": gpio_pin})
                break

    return sequence


def print_sequence(sequence):
    print("\n" + "=" * 50)
    print("CUTTING SEQUENCE")
    print("=" * 50)
    print(f"{'STEP':<6} {'GPIO':<6}")
    print("-" * 50)

    for step in sequence:
        print(f"{step['step']:<6} {step['gpio_pin']:<6}")

    print("=" * 50)


def save_to_file(seed_string, sequence):
    filename = f"sequence_{seed_string}.txt"
    with open(filename, "w") as f:
        f.write(f"Seed: {seed_string}\n\n")
        f.write(f"{'STEP':<6} {'GPIO':<6}\n")
        f.write("-" * 50 + "\n")
        for step in sequence:
            f.write(f"{step['step']:<6} {step['gpio_pin']:<6}\n")

    print(f"\nSaved to: {filename}")


def main():
    print("\n" + "BOMB" * 25)
    print("Ground Truth Bomb Defuse Tool")
    print("BOMB" * 25)

    print("\nGPIO Mapping:")
    print("  Logical Pin 0 -> GPIO 8")
    print("  Logical Pin 1-7 -> GPIO 9-15")
    print("  Logical Pin 8 -> GPIO 0")
    print("  Logical Pin 9-15 -> GPIO 22-16")

    print("\n" + "=" * 50)
    print("ENTER THE SEED")
    print("=" * 50)
    print("  Device shows: S/N: xxxxxxxxxx")
    print("  Enter 10 hex characters")
    print("  Example: deadbeef01")

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

            print(f"\nCalculating sequence...")

            sequence = generate_cutting_sequence(seed)

            print_sequence(sequence)
            save_to_file(seed, sequence)

        except EOFError:
            print("\nBye!")
            break


if __name__ == "__main__":
    main()
