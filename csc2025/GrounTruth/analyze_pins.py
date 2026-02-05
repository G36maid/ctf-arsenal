#!/usr/bin/env python3
"""
Analyze Ground Truth firmware pin mapping logic
"""

import hashlib


def sha512_double(data):
    """Double SHA512 hash (as used in firmware)"""
    first = hashlib.sha512(data).digest()
    second = hashlib.sha512(first).digest()
    return second


def calculate_pins_order(seed_string):
    """
    Replicate the calculate_pins_order function from firmware
    """
    # Convert seed string to bytes
    seed_bytes = seed_string.encode("ascii")

    # Double SHA512
    hash_result = sha512_double(seed_bytes)

    # Initialize pins_order to zeros
    pins_order = [0] * 16

    # Count bits for each position (hash is 64 bytes = 512 bits)
    for j in range(64):
        for i in range(8):
            if (hash_result[j] >> i) & 1:
                idx = (j * 8 + i) % 16
                pins_order[idx] += 1

    # Create pairs array for sorting
    pairs = []
    for i in range(16):
        pairs.append({"original_index": pins_order[i], "value": i})

    # Bubble sort by original_index, then by value (for ties)
    for j1 in range(15):
        for i4 in range(15 - j1):
            if pairs[i4]["original_index"] < pairs[i4 + 1]["original_index"] or (
                pairs[i4]["original_index"] == pairs[i4 + 1]["original_index"]
                and pairs[i4 + 1]["value"] < pairs[i4]["value"]
            ):
                # Swap
                temp_orig = pairs[i4 + 1]["original_index"]
                temp_val = pairs[i4 + 1]["value"]
                pairs[i4 + 1]["original_index"] = pairs[i4]["original_index"]
                pairs[i4 + 1]["value"] = pairs[i4]["value"]
                pairs[i4]["original_index"] = temp_orig
                pairs[i4]["value"] = temp_val

    # Assign ranks (positions in sorted order)
    ranks = [0] * 16
    for i5 in range(16):
        ranks[pairs[i5]["value"]] = i5 + 1

    # Final pins_order is the ranks
    pins_order = ranks

    return pins_order, hash_result


def analyze_seed_hex(seed_hex):
    """
    Analyze a seed string in hex format
    """
    if len(seed_hex) != 10:
        print(f"Warning: seed_hex length is {len(seed_hex)}, expected 10")

    pins_order, hash_result = calculate_pins_order(seed_hex)

    print(f"\nSeed: {seed_hex}")
    print(f"Pins Order (rank): {pins_order}")
    print(f"\nPin # | Rank (when to cut)")
    print("-" * 30)
    for i, rank in enumerate(pins_order):
        status = "✓ CUT FIRST" if rank == 1 else f"  rank {rank}"
        print(f"  {i:2d}   | {status}")


def main():
    print("=" * 60)
    print("Ground Truth Pin Mapping Analysis")
    print("=" * 60)

    print("\nUnderstanding the logic:")
    print("- Each pin has a 'rank' value (1-16)")
    print("- Cut pins in order: rank 1 first, then rank 2, etc.")
    print("- Cutting wrong pin = explosion")
    print("- When all pins rank 0, you win!")

    print("\nFrom challenge hints:")
    print("- Left-top corner: GPIO 8")
    print("- Right-top corner: GPIO 0")
    print("- 16 pins total (0-15)")

    print("\n" + "=" * 60)
    print("The check_pins[16] array maps physical pins to logical pins")
    print("=" * 60)

    print("\nTo solve this challenge, you need:")
    print("1. Read the seed from EEPROM (addresses 2-6, 5 bytes)")
    print("2. Convert to hex string (e.g., 'a1b2c3d4e5')")
    print("3. Calculate pins_order to know the cutting order")
    print("4. Map logical pins to physical GPIO pins")

    print("\n" + "=" * 60)
    print("Example Analysis")
    print("=" * 60)

    # Try some example seeds
    example_seeds = [
        "0000000000",  # All zeros
        "ffffffffff",  # All f's
        "0123456789",  # Sequential
        "deadbeef01",  # Example hex
    ]

    for seed in example_seeds:
        analyze_seed_hex(seed)

    print("\n" + "=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Extract check_pins[16] values from firmware binary")
    print("   (This array maps GPIO pins to logical pin indices)")
    print("2. Get the seed from EEPROM or device display")
    print("3. Run analysis with actual seed")
    print("4. Follow the cutting order to defuse!")


if __name__ == "__main__":
    main()
