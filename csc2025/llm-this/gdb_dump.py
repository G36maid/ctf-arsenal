#!/usr/bin/env python3
import subprocess
import time

# Start the process with GDB
gdb_commands = """
set pagination off
set logging file memory_dump.txt
set logging on
break *main
run <<< "test"
info proc mappings
x/2000xb 0x555555554000
x/2000xb 0x555555556000
quit
"""

with open('/tmp/gdb_commands.txt', 'w') as f:
    f.write(gdb_commands)

subprocess.run(['gdb', '-batch', '-x', '/tmp/gdb_commands.txt', './llm-this'], 
               capture_output=False)
