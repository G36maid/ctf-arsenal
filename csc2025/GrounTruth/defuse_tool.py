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
                position = ""
                if gpio_pin == 8:
                    position = "[LEFT-TOP]"
                elif gpio_pin == 0:
                    position = "[RIGHT-TOP]"
                elif 16 <= gpio_pin <= 22:
                    position = "BOTTOM"
                elif 9 <= gpio_pin <= 15:
                    position = "RIGHT"

                direction = get_direction(gpio_pin)
                sequence.append(
                    {
                        "step": rank,
                        "rank": rank,
                        "logical_pin": logical_pin,
                        "gpio_pin": gpio_pin,
                        "position": position,
                        "direction": direction,
                    }
                )
                break

    return sequence


def get_direction(gpio_pin):
    if gpio_pin == 8:
        return "TOP-LEFT"
    elif gpio_pin == 0:
        return "TOP-RIGHT"
    elif 9 <= gpio_pin <= 15:
        return "RIGHT-COLUMN"
    elif 16 <= gpio_pin <= 22:
        return "BOTTOM-ROW"
    return "UNKNOWN"


def print_visual_board():
    print("\n" + "=" * 70)
    print("CIRCUIT BOARD LAYOUT")
    print("=" * 70)
    print("""
    +------------------------------+
    |  GPIO 8  |  GPIO 0     |  <-- Top Markers
    |  (Pin 0)  |  (Pin 8)     |
    +------------------------------+
    |  GPIO 9-15                |  <-- Right Column (Pin 1-7)
    +------------------------------+
    |  GPIO 22-16                |  <-- Bottom Row (Pin 9-15)
    +------------------------------+
    """)


def print_cutting_sequence(sequence):
    print("\n" + "=" * 70)
    print("COMPLETE CUTTING SEQUENCE")
    print("=" * 70)
    print(f"{'STEP':<6} {'GPIO':<6} {'LOGIC':<10} {'POSITION':<20} {'DESCRIPTION'}")
    print("-" * 70)

    for step in sequence:
        print(
            f"{step['step']:<6} {step['gpio_pin']:<6} {step['logical_pin']:<10} "
            f"{step['position']:<20} {step['direction']}"
        )

    print("\n" + "=" * 70)
    print("OPERATION INSTRUCTIONS")
    print("=" * 70)
    print("1. Cut wires in step order shown above")
    print("2. After each correct cut, remaining pins' ranks decrease by 1")
    print("3. Cutting in wrong order = EXPLOSION")
    print("4. Cutting all correctly = FLAG!")


def create_quick_reference(sequence):
    print("\n" + "=" * 70)
    print("QUICK REFERENCE CARD")
    print("=" * 70)

    print("\n[TOP - Key Markers]")
    top_pins = [s for s in sequence if s["gpio_pin"] in [8, 0]]
    for pin in top_pins:
        marker = "Left-Top" if pin["gpio_pin"] == 8 else "Right-Top"
        print(f"  Step {pin['step']:2d}: GPIO {pin['gpio_pin']:2d} [{marker}]")

    print("\n[RIGHT - GPIO 9-15]")
    right_pins = [s for s in sequence if 9 <= s["gpio_pin"] <= 15]
    for pin in right_pins:
        print(f"  Step {pin['step']:2d}: GPIO {pin['gpio_pin']:2d}")

    print("\n[BOTTOM - GPIO 22-16 (left to right)]")
    bottom_pins = [s for s in sequence if 16 <= s["gpio_pin"] <= 22]
    for pin in bottom_pins:
        print(f"  Step {pin['step']:2d}: GPIO {pin['gpio_pin']:2d}")


def save_to_file(seed_string, sequence):
    filename = f"cutting_sequence_{seed_string}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"Ground Truth Bomb - Cutting Sequence (Seed: {seed_string})\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"{'STEP':<6} {'GPIO':<6} {'LOGIC':<10} {'POSITION':<20}\n")
        f.write("-" * 70 + "\n")
        for step in sequence:
            f.write(
                f"{step['step']:<6} {step['gpio_pin']:<6} {step['logical_pin']:<10} "
                f"{step['position']:<20}\n"
            )

        f.write("\n" + "=" * 70 + "\n")
        f.write("IMPORTANT NOTES:\n")
        f.write("=" * 70 + "\n")
        f.write("1. Left-Top GPIO 8 -> This is the first key marker\n")
        f.write("2. Right-Top GPIO 0 -> This is the last key marker\n")
        f.write("3. Cut from step 1 to 16 in order\n")
        f.write("4. Cutting wrong order = EXPLOSION\n")
        f.write("5. Cutting all correctly = FLAG displayed\n")

    print(f"\n[OK] Complete sequence saved to: {filename}")


def main():
    print("\n" + "TARGET" * 35)
    print("Ground Truth Bomb Defuse Tool")
    print("TARGET" * 35)

    print_visual_board()

    print("=" * 70)
    print("ENTER THE SEED FROM YOUR DEVICE")
    print("=" * 70)
    print("\nFormat instructions:")
    print("  - Device shows: S/N: xxxxxxxxxx")
    print("  - Enter those 10 characters (without 'S/N:')")
    print("  - Example: deadbeef01, 1234567890, abcdef0123")

    while True:
        try:
            seed = input("\n[INPUT] Enter Seed (or type 'quit' to exit): ").strip()

            if seed.lower() == "quit":
                print("\n[EXIT] Good luck!")
                break

            if len(seed) != 10:
                print("[ERROR] Seed must be 10 characters")
                continue

            if not all(c.lower() in "0123456789abcdef" for c in seed):
                print("[ERROR] Seed can only contain 0-9 and a-f")
                continue

            print(f"\n[OK] Seed received: {seed}")
            print("[INFO] Calculating cutting sequence...\n")

            sequence = generate_cutting_sequence(seed)

            print_cutting_sequence(sequence)
            create_quick_reference(sequence)
            save_to_file(seed, sequence)

            print("\n" + "=" * 70)
            print("[READY] Follow the sequence to defuse the bomb!")
            print("=" * 70)

        except EOFError:
            print("\n[EXIT] Good luck!")
            break


if __name__ == "__main__":
    main()
