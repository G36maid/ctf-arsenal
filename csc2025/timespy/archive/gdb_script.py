#!/usr/bin/env python3
import gdb
import sys

# Break at mem.eql comparison
gdb.execute("file ./timespy")
gdb.execute("set pagination off")
gdb.execute("set logging file gdb_output.txt")
gdb.execute("set logging overwrite on")
gdb.execute("set logging on")

# Break right before the flag comparison at 0x113dd35
gdb.execute("b *0x113dd35")
gdb.execute("commands")
gdb.execute("silent")
gdb.execute('printf "[*] At flag comparison\\n"')
gdb.execute('printf "RAX (decrypted input): 0x%lx\\n", $rax')
gdb.execute('printf "RDX (length): %lu\\n", $rdx')
gdb.execute("x/29bx $rax")
gdb.execute('printf "RBX (expected flag addr): 0x%lx\\n", $rbx')
gdb.execute('printf "RCX (length): %lu\\n", $rcx')
gdb.execute("x/29bx $rbx")
gdb.execute("continue")
gdb.execute("end")

# Provide input
input_data = "A" * 29 + "\n"
gdb.execute(f"r <<< '{input_data}'")
gdb.execute("quit")
