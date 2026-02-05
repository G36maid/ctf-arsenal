#!/usr/bin/env python3
"""
Pwntools Basic Template for CTF
Usage:
    python pwn_basic.py                  # Local process
    python pwn_basic.py GDB              # GDB debug mode
    python pwn_basic.py REMOTE IP PORT   # Remote connection
"""

from pwn import *

# ===== 設定 =====
exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

# ===== Libc 設定 (如果需要) =====
# libc = ELF('./libc.so.6', checksec=False)


# ===== 啟動函數 =====
def start(argv=[], *a, **kw):
    """自動切換 Local/GDB/Remote"""
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# ===== GDB Script =====
gdbscript = """
# 載入 GEF/Pwndbg/PEDA
init-gef

# 設定中斷點
# b *main
# b *main+123

# 繼續執行
continue
""".format(**locals())


# ===== 工具函數 =====
def leak_address(data):
    """從 leaked data 提取地址"""
    return u64(data.ljust(8, b"\x00"))


def find_offset():
    """使用 cyclic pattern 找 offset"""
    io = start()
    io.sendline(cyclic(500))
    io.wait()
    core = io.corefile
    offset = cyclic_find(core.read(core.rsp, 4))
    info(f"Offset found: {offset}")
    return offset


# ===== 主要 Exploit =====
io = start()

# ===== Stage 1: 資訊洩漏 (如果需要) =====
# io.sendlineafter(b'>', payload_leak)
# leaked = io.recvline()
# base_addr = leak_address(leaked) - offset
# info(f'Base address: {hex(base_addr)}')

# ===== Stage 2: 構建 Payload =====
# offset = 72
# payload = flat({
#     offset: [
#         # ROP chain here
#         pop_rdi,
#         next(elf.search(b'/bin/sh\x00')),
#         elf.plt['system']
#     ]
# })

# ===== Stage 3: 發送 Payload =====
# io.sendlineafter(b'Input: ', payload)

# ===== 獲取 Shell =====
io.interactive()
