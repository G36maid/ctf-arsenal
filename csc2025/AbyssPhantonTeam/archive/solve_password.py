#!/usr/bin/env python3
"""
Password validation reverse engineering from ghost_decrypted_correct.exe

From main::main_validatePassword (line 134271):
1. Password length MUST be 15 bytes (line 134304)
2. Sum of all bytes MUST equal 0x415 = 1045 (line 134316)
3. password[0] ^ password[1] ^ password[2] ^ password[3] == 0x61 (line 134341)
4. password[4] * password[5] * password[6] * password[7] == 0 (line 134366)
   This means at least one of these 4 bytes must be 0
5. Sum of squares of password[7:15] % 100 == 0x3d = 61 (line 134377-134378)
"""


def check_password_constraints(password):
    """
    Validate password against all constraints from the decompilation.
    """
    if len(password) != 15:
        return False, "Length must be 15"

    # Convert to bytes if string
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    if len(password_bytes) != 15:
        return False, f"UTF-8 length must be 15, got {len(password_bytes)}"

    # Constraint 1: Sum of all bytes == 1045
    total_sum = sum(password_bytes)
    if total_sum != 0x415:
        return False, f"Sum of bytes must be 1045, got {total_sum}"

    # Constraint 2: XOR of first 4 bytes == 0x61 ('a')
    xor_result = (
        password_bytes[0] ^ password_bytes[1] ^ password_bytes[2] ^ password_bytes[3]
    )
    if xor_result != 0x61:
        return False, f"XOR of first 4 bytes must be 0x61, got {hex(xor_result)}"

    # Constraint 3: Product of bytes 4-7 == 0 (at least one must be 0)
    product = (
        password_bytes[4] * password_bytes[5] * password_bytes[6] * password_bytes[7]
    )
    if product != 0:
        return False, f"Product of bytes[4:8] must be 0, got {product}"

    # Constraint 4: Sum of squares of bytes 7-14 mod 100 == 61
    sum_of_squares = sum(b * b for b in password_bytes[7:15])
    if sum_of_squares % 100 != 0x3D:
        return (
            False,
            f"Sum of squares of bytes[7:15] % 100 must be 61, got {sum_of_squares % 100}",
        )

    return True, "All constraints satisfied"


def solve_password():
    """
    Try to find a password that satisfies all constraints.
    We know:
    - Length = 15
    - Sum = 1045 (average ~69.67 per byte, printable ASCII range)
    - One of bytes[4:8] must be 0
    - Complex XOR and modulo constraints
    """
    import itertools

    # Try printable ASCII characters (32-126)
    # Given sum constraint, likely uses mostly printable chars

    # Let's try a smarter approach: brute force with constraints
    # Start with common patterns

    # If we assume password[7] = 0 (null byte), that simplifies constraint 3
    # But then password[7:15] starts with 0, affecting sum of squares

    # Let's try to work backwards from the constraints
    # For sum of squares % 100 == 61:
    # We need 8 bytes (password[7:15]) whose squares sum to something % 100 == 61

    # Common ASCII values and their squares:
    # 'a' (97): 9409 % 100 = 9
    # 'e' (101): 10201 % 100 = 1
    # 'i' (105): 11025 % 100 = 25
    # 'o' (111): 12321 % 100 = 21
    # 'u' (117): 13689 % 100 = 89
    # '0' (48): 2304 % 100 = 4
    # ' ' (32): 1024 % 100 = 24

    print("Password constraints:")
    print("1. Length = 15")
    print("2. Sum of bytes = 1045")
    print("3. bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3] = 0x61")
    print("4. bytes[4] * bytes[5] * bytes[6] * bytes[7] = 0")
    print("5. sum(bytes[7:15]^2) % 100 = 61")
    print()

    # Try to extract from binary or use known patterns
    # Let's check if there's a hardcoded password in the binary

    return None


def test_known_passwords():
    """Test some candidate passwords."""
    candidates = [
        "cschahaha" + "0" * 6,  # Pad to 15
        "AbyssPhan" + "tom000",
        "seadog007" + "000000",
    ]

    for pwd in candidates:
        valid, msg = check_password_constraints(pwd)
        print(f"Testing: {pwd!r}")
        print(f"  Result: {msg}")
        if valid:
            print(f"  ✓ FOUND VALID PASSWORD: {pwd}")
            return pwd
        print()

    return None


if __name__ == "__main__":
    print("=" * 60)
    print("Password Constraint Solver")
    print("=" * 60)
    print()

    # Test if we can find the password
    solve_password()

    print("\nTesting known password candidates:")
    print("-" * 60)
    found = test_known_passwords()

    if not found:
        print("\n" + "=" * 60)
        print("No password found yet. Need to:")
        print("1. Extract encrypted data from PE")
        print("2. Brute force with wordlist")
        print("3. Or solve the constraint equations")
        print("=" * 60)
