#!/usr/bin/env python3
"""
Offset Finder - Find buffer overflow offset using cyclic pattern
Usage:
    python offset_finder.py <binary> [pattern_length]
    python offset_finder.py ./vuln 1000
    python offset_finder.py ./vuln 2000 GDB
"""

import sys
from pwn import *


def find_offset(binary, pattern_length=1000, use_gdb=False):
    """Find offset to RIP/EIP using cyclic pattern"""

    exe = binary
    elf = context.binary = ELF(exe, checksec=False)
    context.log_level = "debug"

    # Generate cyclic pattern
    pattern = cyclic(pattern_length)

    print(f"[*] Binary: {binary}")
    print(f"[*] Pattern length: {pattern_length}")
    print(f"[*] Sending cyclic pattern...")

    if use_gdb:
        gdbscript = """
        # Run until crash
        continue
        """
        io = gdb.debug([exe], gdbscript=gdbscript)
    else:
        io = process([exe])

    io.sendline(pattern)
    io.wait()

    print(f"[*] Process crashed. Check register values.")
    print(f"[*] In GDB: 'cyclic_find <value_from_rip/eip>'")
    print(f"[*] Or use this script's output below:")
    print(f"")

    # Try to read core file if available
    try:
        core = io.corefile
        if core:
            offset = cyclic_find(core.rip)
            print(f"[+] Offset to RIP: {offset}")
            return offset
    except:
        pass

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python offset_finder.py <binary> [pattern_length] [GDB]")
        print("Example: python offset_finder.py ./vuln 1000")
        print("Example: python offset_finder.py ./vuln 2000 GDB")
        sys.exit(1)

    binary = sys.argv[1]
    pattern_length = (
        int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1000
    )
    use_gdb = "GDB" in sys.argv

    try:
        offset = find_offset(binary, pattern_length, use_gdb)
        if offset:
            print(f"[+] Offset found: {offset}")
        else:
            print("[-] Could not determine offset automatically")
            print("[*] Manual method:")
            print("    1. Run: ./binary < input")
            print("    2. Copy RIP value from crash")
            print(
                '    3. Run: python -c "from pwn import *; print(cyclic_find(0x<rip_value>))"'
            )
    except FileNotFoundError:
        print(f"[-] Binary not found: {binary}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
