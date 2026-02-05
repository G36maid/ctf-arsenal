#!/usr/bin/env python3
"""
Brainfuck Interpreter
Purpose: Execute and debug Brainfuck esoteric language code
Usage:
    python3 bf_decode.py code.bf [input_file]
    python3 bf_decode.py -c "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
"""

import sys
from collections import defaultdict


class BrainfuckInterpreter:
    """Simple Brainfuck interpreter with debug mode"""

    def __init__(self, memory_size=30000):
        self.memory = defaultdict(int)
        self.pointer = 0
        self.output = []
        self.input_data = ""
        self.input_ptr = 0
        self.memory_size = memory_size
        self.debug = False

    def load_input(self, input_str):
        """Load input string for ',' operations"""
        self.input_data = input_str
        self.input_ptr = 0

    def _find_matching_bracket(self, code, pos, direction):
        """Find matching [ or ] bracket"""
        bracket_map = {"[": ("]", 1), "]": ("[", -1)}
        target, step = bracket_map[code[pos]]
        depth = 1
        pos += step

        while 0 <= pos < len(code) and depth > 0:
            if code[pos] == code[pos - step] if step == 1 else code[pos]:
                if (
                    code[pos]
                    == bracket_map.get(code[pos - step] if step == 1 else "", "")[0]
                ):
                    depth += 1
                elif code[pos] == target:
                    depth -= 1
            pos += step

        return pos - step if depth == 0 else -1

    def _find_matching_bracket_simple(self, code, pos, direction):
        """Find matching bracket (corrected)"""
        if direction == 1:  # Looking for ]
            depth = 1
            i = pos + 1
            while i < len(code):
                if code[i] == "[":
                    depth += 1
                elif code[i] == "]":
                    depth -= 1
                    if depth == 0:
                        return i
                i += 1
        else:  # Looking for [
            depth = 1
            i = pos - 1
            while i >= 0:
                if code[i] == "]":
                    depth += 1
                elif code[i] == "[":
                    depth -= 1
                    if depth == 0:
                        return i
                i -= 1
        return -1

    def execute(self, code):
        """Execute Brainfuck code"""
        # Clean code - keep only valid instructions
        valid = set(".,<>+-[]")
        code = "".join(c for c in code if c in valid)

        ip = 0  # Instruction pointer

        while ip < len(code):
            cmd = code[ip]

            if cmd == ">":
                self.pointer += 1
                if self.pointer >= self.memory_size:
                    raise RuntimeError(f"Memory access out of bounds: {self.pointer}")

            elif cmd == "<":
                self.pointer -= 1
                if self.pointer < 0:
                    raise RuntimeError(f"Memory pointer went negative: {self.pointer}")

            elif cmd == "+":
                self.memory[self.pointer] = (self.memory[self.pointer] + 1) % 256

            elif cmd == "-":
                self.memory[self.pointer] = (self.memory[self.pointer] - 1) % 256

            elif cmd == ".":
                self.output.append(chr(self.memory[self.pointer]))

            elif cmd == ",":
                if self.input_ptr < len(self.input_data):
                    self.memory[self.pointer] = ord(self.input_data[self.input_ptr])
                    self.input_ptr += 1
                else:
                    self.memory[self.pointer] = 0

            elif cmd == "[":
                if self.memory[self.pointer] == 0:
                    ip = self._find_matching_bracket_simple(code, ip, 1)
                    if ip == -1:
                        raise RuntimeError("Unmatched [")

            elif cmd == "]":
                if self.memory[self.pointer] != 0:
                    ip = self._find_matching_bracket_simple(code, ip, -1)
                    if ip == -1:
                        raise RuntimeError("Unmatched ]")

            ip += 1

        return "".join(self.output)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 bf_decode.py <code_file or -c 'code'> [input_file]")
        sys.exit(1)

    # Load code
    if sys.argv[1] == "-c":
        if len(sys.argv) < 3:
            print("Error: -c requires code argument")
            sys.exit(1)
        code = sys.argv[2]
        input_file = sys.argv[3] if len(sys.argv) > 3 else None
    else:
        code_file = sys.argv[1]
        try:
            with open(code_file, "r") as f:
                code = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {code_file}")
            sys.exit(1)
        input_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Load input
    input_data = ""
    if input_file:
        try:
            with open(input_file, "r") as f:
                input_data = f.read()
        except FileNotFoundError:
            print(f"Error: Input file not found: {input_file}")
            sys.exit(1)

    # Execute
    interpreter = BrainfuckInterpreter()
    interpreter.load_input(input_data)

    try:
        result = interpreter.execute(code)
        print(result, end="")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
