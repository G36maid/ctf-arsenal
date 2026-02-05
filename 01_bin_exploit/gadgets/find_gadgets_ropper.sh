#!/bin/bash
# Find ROP gadgets using ropper
# Usage: find_gadgets_ropper.sh <binary> [gadget_pattern]
# Example: find_gadgets_ropper.sh ./vuln "pop rdi"

if [ $# -lt 1 ]; then
	echo "Usage: $0 <binary> [gadget_pattern]"
	echo "Example: $0 ./vuln 'pop rdi'"
	exit 1
fi

BINARY=$1
PATTERN=${2:-"pop"}

# Check if ropper is installed
if ! command -v ropper &>/dev/null; then
	echo "[-] ropper not found. Install: pip install ropper"
	exit 1
fi

echo "[*] Searching for gadgets: $PATTERN"
echo "[*] Binary: $BINARY"
echo ""

# ropper is interactive, so we use --search flag
ropper --file "$BINARY" --search "$PATTERN" 2>/dev/null | head -30
echo ""
echo "[+] For detailed search: ropper --file $BINARY --search 'pop rdi; ret'"
