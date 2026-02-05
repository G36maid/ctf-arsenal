#!/bin/bash
# Find ROP gadgets using ROPgadget
# Usage: find_gadgets_ropgadget.sh <binary> [gadget_pattern]
# Example: find_gadgets_ropgadget.sh ./vuln "pop rdi"

if [ $# -lt 1 ]; then
	echo "Usage: $0 <binary> [gadget_pattern]"
	echo "Example: $0 ./vuln 'pop rdi'"
	exit 1
fi

BINARY=$1
PATTERN=${2:-"pop rdi"}

# Check if ROPgadget is installed
if ! command -v ROPgadget &>/dev/null; then
	echo "[-] ROPgadget not found. Install: pip install ropgadget"
	exit 1
fi

echo "[*] Searching for gadgets: $PATTERN"
echo "[*] Binary: $BINARY"
echo ""

ROPgadget --file "$BINARY" --string "$PATTERN" 2>/dev/null | head -20
echo ""
echo "[+] Run without pattern for all gadgets: ROPgadget --file $BINARY | grep -E '(pop|mov|ret)'"
