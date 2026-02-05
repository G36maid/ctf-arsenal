#!/usr/bin/env python3
"""
Libc Lookup - Find symbols and offsets in libc
Usage:
    python libc_lookup.py <libc_path> <symbol_name>
    python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 puts
    python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 system
    python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 dup2
"""

import sys
from pwn import *


def lookup_symbol(libc_path, symbol_name):
    """Look up symbol in libc and return offset"""

    try:
        libc = ELF(libc_path, checksec=False)
    except FileNotFoundError:
        print(f"[-] Libc not found: {libc_path}")
        return None

    print(f"[*] Libc: {libc_path}")
    print(f"[*] Searching for: {symbol_name}")
    print("")

    # Try exact symbol first
    if symbol_name in libc.symbols:
        offset = libc.symbols[symbol_name]
        print(f"[+] Found symbol: {symbol_name}")
        print(f"[+] Offset: 0x{offset:x}")
        print(f"[+] Usage in exploit:")
        print(f"    libc_base = leaked_address - 0x{offset:x}")
        print(f"    {symbol_name}_addr = libc_base + 0x{offset:x}")
        return offset

    # Try to find partial matches
    matches = [s for s in libc.symbols if symbol_name.lower() in s.lower()]
    if matches:
        print(f"[-] Exact symbol not found, but found {len(matches)} partial matches:")
        for match in matches[:10]:  # Show first 10
            offset = libc.symbols[match]
            print(f"    {match}: 0x{offset:x}")
    else:
        print(f"[-] Symbol '{symbol_name}' not found in libc")
        print(f"[*] Available symbols: use 'nm {libc_path}' to list all")

    return None


def main():
    if len(sys.argv) < 3:
        print("Usage: python libc_lookup.py <libc_path> <symbol_name>")
        print("")
        print("Examples:")
        print("  python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 puts")
        print("  python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 system")
        print("  python libc_lookup.py /lib/x86_64-linux-gnu/libc.so.6 dup2")
        print("")
        print("Common symbols in libc:")
        print("  - puts, printf (output)")
        print("  - system (execute shell)")
        print("  - dup2 (file descriptor manipulation)")
        print("  - execve (execute program)")
        print("  - read, write (I/O)")
        sys.exit(1)

    libc_path = sys.argv[1]
    symbol_name = sys.argv[2]

    lookup_symbol(libc_path, symbol_name)


if __name__ == "__main__":
    main()
