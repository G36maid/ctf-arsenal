#!/usr/bin/env python3
"""
GDB script to understand the exception flow
"""

gdb_commands = """
set pagination off
set confirm off

# Break at wish_ultimate_power entry
b *0x402102
commands
    silent
    printf "\\n[*] Entered wish_ultimate_power()\\n"
    printf "    RSP: %p\\n", $rsp
    printf "    RBP: %p\\n", $rbp
    continue
end

# Break at the try block start
b *0x40211e
commands
    silent
    printf "\\n[*] At try block (nop instruction)\\n"
    x/10i $rip
    continue
end

# Break at exception handler
b *0x40214c
commands
    silent
    printf "\\n[!!!] EXCEPTION HANDLER TRIGGERED!\\n"
    printf "    RAX (exception ptr): %p\\n", $rax
    printf "    RDX (exception type): %p\\n", $rdx
    info registers
    continue
end

# Break at system() call
b *0x4021d3
commands
    silent
    printf "\\n[!!!] CALLING system()!\\n"
    x/s $rdi
    continue
end

# Break at cast_special_skill
b *0x401476
commands
    silent
    printf "\\n[*] Entered cast_special_skill()\\n"
    continue
end

# Break at exception throw in cast_special_skill
b *0x40158d
commands
    silent
    printf "\\n[!!!] THROWING EXCEPTION in cast_special_skill!\\n"
    printf "    Exception ptr: %p\\n", $rax
    printf "    Exception message: "
    x/s *($rax)
    continue
end

run
"""

with open("/tmp/gdb_playgame.txt", "w") as f:
    f.write(gdb_commands)

print("[+] GDB script written to /tmp/gdb_playgame.txt")
print()
print("Run with:")
print(
    "  (echo 'TestPlayer'; sleep 1; for i in {1..20}; do echo 1; sleep 0.2; done; echo 2; sleep 5) | gdb -x /tmp/gdb_playgame.txt ./game_server.bin"
)
