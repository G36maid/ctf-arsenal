#!/usr/bin/env python3
"""
Fast Parser Template
Purpose: Template for parsing structured data (JSON, CSV, binary, custom formats)
Usage:
    python3 fast_parse.py input.txt
    python3 fast_parse.py -j input.json
    python3 fast_parse.py -csv input.csv
"""

import sys
import json
import csv
import re
from collections import defaultdict


class FastParser:
    """Fast parser for various data formats"""

    def __init__(self):
        self.data = []
        self.parsed = {}

    def parse_json(self, content):
        """Parse JSON data"""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"[-] JSON parse error: {e}", file=sys.stderr)
            return None

    def parse_csv(self, content):
        """Parse CSV data"""
        lines = content.strip().split("\n")
        reader = csv.DictReader(lines)
        return list(reader)

    def parse_hex(self, content):
        """Parse hex-encoded data"""
        # Remove whitespace and convert
        hex_str = content.replace(" ", "").replace("\n", "")
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
        except ValueError as e:
            print(f"[-] Hex parse error: {e}", file=sys.stderr)
            return None

    def parse_base64(self, content):
        """Parse base64-encoded data"""
        import base64

        try:
            return base64.b64decode(content.strip()).decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"[-] Base64 parse error: {e}", file=sys.stderr)
            return None

    def parse_url_encoded(self, content):
        """Parse URL-encoded data"""
        import urllib.parse

        return urllib.parse.unquote(content.strip())

    def parse_custom(self, content, pattern):
        """Parse using regex pattern"""
        matches = re.findall(pattern, content)
        return matches

    def parse_key_value(self, content):
        """Parse key=value format"""
        result = {}
        for line in content.strip().split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
        return result

    def parse_newline_separated(self, content):
        """Parse newline-separated values"""
        return [line.strip() for line in content.strip().split("\n") if line.strip()]


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 fast_parse.py [-j|-csv|-hex|-b64|-kv|-regex] <input_file>"
        )
        print("")
        print("Options:")
        print("  -j         Parse as JSON")
        print("  -csv       Parse as CSV")
        print("  -hex       Parse hex-encoded data")
        print("  -b64       Parse base64-encoded data")
        print("  -kv        Parse key=value format")
        print("  -url       Parse URL-encoded data")
        print("  -lines     Parse as newline-separated values")
        print("  -regex PATTERN  Parse using regex pattern")
        print("")
        print("Examples:")
        print("  python3 fast_parse.py -j data.json")
        print("  python3 fast_parse.py -hex data.hex")
        print("  python3 fast_parse.py -regex '[a-z]+' data.txt")
        sys.exit(1)

    parser = FastParser()

    # Parse arguments
    mode = "auto"
    pattern = None
    input_file = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "-j":
            mode = "json"
        elif arg == "-csv":
            mode = "csv"
        elif arg == "-hex":
            mode = "hex"
        elif arg == "-b64":
            mode = "base64"
        elif arg == "-kv":
            mode = "keyvalue"
        elif arg == "-url":
            mode = "urlencoded"
        elif arg == "-lines":
            mode = "lines"
        elif arg == "-regex":
            mode = "regex"
            i += 1
            if i < len(sys.argv):
                pattern = sys.argv[i]
        else:
            input_file = arg
        i += 1

    if not input_file:
        print("[-] No input file specified", file=sys.stderr)
        sys.exit(1)

    # Read file
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] File not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    # Parse
    result = None
    if mode == "json":
        result = parser.parse_json(content)
    elif mode == "csv":
        result = parser.parse_csv(content)
    elif mode == "hex":
        result = parser.parse_hex(content)
    elif mode == "base64":
        result = parser.parse_base64(content)
    elif mode == "keyvalue":
        result = parser.parse_key_value(content)
    elif mode == "urlencoded":
        result = parser.parse_url_encoded(content)
    elif mode == "lines":
        result = parser.parse_newline_separated(content)
    elif mode == "regex":
        if not pattern:
            print("[-] Regex mode requires -regex PATTERN", file=sys.stderr)
            sys.exit(1)
        result = parser.parse_custom(content, pattern)
    else:
        # Auto-detect
        try:
            result = parser.parse_json(content)
            if result:
                print("[+] Detected JSON format")
        except:
            result = parser.parse_csv(content)
            if result:
                print("[+] Detected CSV format")
            else:
                result = parser.parse_newline_separated(content)

    # Output
    if result is None:
        print("[-] Parse failed", file=sys.stderr)
        sys.exit(1)

    if isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
