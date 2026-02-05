#!/usr/bin/env python3
"""
Leak Parser - Parse leaked values from binary output
Converts leaked addresses to offsets and symbols
Usage:
    python leak_parser.py <binary> <leaked_hex_value> [symbol_name]
    python leak_parser.py ./vuln 0x7ffff7daa000
    python leak_parser.py ./vuln 0x7ffff7a64800 puts
"""

import sys
from pwn import *


def parse_leak(binary, leaked_value, symbol_name=None):
    """Parse leaked address and find offset/symbol"""

    try:
        elf = ELF(binary, checksec=False)
    except FileNotFoundError:
        print(f"[-] Binary not found: {binary}")
        return

    if isinstance(leaked_value, str):
        try:
            leaked_value = int(leaked_value, 16)
        except ValueError:
            print(f"[-] Invalid hex value: {leaked_value}")
            return

    print(f"[*] Binary: {binary}")
    print(f"[*] Leaked value: 0x{leaked_value:x}")
    print("")

    # If it looks like a libc address (high memory)
    if leaked_value > 0x7F0000000000:
        print("[*] Detected possible libc leak (high memory address)")

        # Try to match against known symbols
        if symbol_name:
            try:
                symbol_offset = elf.symbols[symbol_name]
                libc_base = leaked_value - symbol_offset
                print(f"[+] Symbol: {symbol_name}")
                print(f"[+] Symbol offset in binary: 0x{symbol_offset:x}")
                print(f"[+] Calculated libc base: 0x{libc_base:x}")
                return libc_base
            except KeyError:
                print(f"[-] Symbol not found: {symbol_name}")
        else:
            print("[*] To calculate libc_base, provide symbol name:")
            print(f"    python leak_parser.py {binary} 0x{leaked_value:x} puts")
            return None

    # Check if it's an address in the binary
    elif 0x400000 <= leaked_value <= 0x500000:
        print("[*] Detected possible binary address")

        # Try to find in binary sections
        for section in elf.sections:
            if (
                section.header["sh_addr"]
                <= leaked_value
                <= section.header["sh_addr"] + section.header["sh_size"]
            ):
                offset = leaked_value - section.header["sh_addr"]
                print(f"[+] Section: {section.name}")
                print(f"[+] Offset in section: 0x{offset:x}")
                print(f"[+] Absolute offset: 0x{leaked_value:x}")
                return leaked_value

    # Generic address info
    print(f"[*] Address: 0x{leaked_value:x}")
    if symbol_name and symbol_name in elf.symbols:
        print(f"[+] Symbol '{symbol_name}' at: 0x{elf.symbols[symbol_name]:x}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python leak_parser.py <binary> <leaked_hex_value> [symbol_name]")
        print("Examples:")
        print("  python leak_parser.py ./vuln 0x7ffff7daa000")
        print("  python leak_parser.py ./vuln 0x7ffff7a64800 puts")
        print("  python leak_parser.py ./vuln 0x401234")
        sys.exit(1)

    binary = sys.argv[1]
    leaked_value = sys.argv[2]
    symbol_name = sys.argv[3] if len(sys.argv) > 3 else None

    parse_leak(binary, leaked_value, symbol_name)


if __name__ == "__main__":
    main()
