#!/bin/bash
# Find ROP gadgets using rp++ (Rapid++), a fast C++ ROP gadget finder
# Usage: find_gadgets_rpplus.sh <binary> [gadget_pattern]
# Example: find_gadgets_rpplus.sh ./vuln "pop rdi"
# Note: rp++ is the fastest gadget finder for large binaries

if [ $# -lt 1 ]; then
	echo "Usage: $0 <binary> [gadget_pattern]"
	echo "Example: $0 ./vuln 'pop rdi'"
	exit 1
fi

BINARY=$1
PATTERN=${2:-"pop"}

# Check if rp++ is available
if ! command -v rp++ &>/dev/null; then
	echo "[-] rp++ not found. Download from: https://github.com/0vercl0k/rp"
	echo "    Or: apt-get install rp++"
	exit 1
fi

echo "[*] Searching for gadgets with rp++: $PATTERN"
echo "[*] Binary: $BINARY"
echo ""

# rp++ --file <binary> --rop --search-all outputs all gadgets
# Pipe to grep for pattern matching
rp++ --file="$BINARY" --rop 2>/dev/null | grep -i "$PATTERN" | head -20

echo ""
echo "[+] For all gadgets: rp++ --file=$BINARY --rop | less"
echo "[+] rp++ is fastest for large binaries, typically used in production"
