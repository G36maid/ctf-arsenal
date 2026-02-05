#!/usr/bin/env python3
import subprocess
import sys

# Run with different inputs to see if output changes
test_inputs = [
    b"test\n",
    b"CSC{test}\n",
    b"C5C{n0t_th1s_t1m3}\n",
    b"A" * 100 + b"\n",
    b"\n",
]

for inp in test_inputs:
    print(f"\n=== Input: {inp[:50]} ===")
    result = subprocess.run(
        ['./llm-this'],
        input=inp,
        capture_output=True,
        timeout=2
    )
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
    print(f"return code: {result.returncode}")
