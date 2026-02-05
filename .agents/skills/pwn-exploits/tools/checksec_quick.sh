#!/bin/bash
# Quick security check on binary (checksec alternative)
# Usage: checksec_quick.sh <binary>
# Shows NX, ASLR, PIE, Canary, RELRO status

if [ $# -lt 1 ]; then
	echo "Usage: $0 <binary>"
	exit 1
fi

BINARY=$1

if [ ! -f "$BINARY" ]; then
	echo "[-] File not found: $BINARY"
	exit 1
fi

echo "[*] Security Features Check: $BINARY"
echo ""

# Function to check for ELF header
check_nx() {
	local has_pt_gnu_stack=$(readelf -l "$BINARY" 2>/dev/null | grep "GNU_STACK" | grep -c "RWE")
	if [ "$has_pt_gnu_stack" -gt 0 ]; then
		echo "[+] NX: DISABLED (stack executable)"
	else
		echo "[+] NX: ENABLED"
	fi
}

check_pie() {
	local et_dyn=$(readelf -h "$BINARY" 2>/dev/null | grep "Type:" | grep -c "DYN")
	if [ "$et_dyn" -gt 0 ]; then
		echo "[+] PIE: ENABLED"
	else
		echo "[+] PIE: DISABLED"
	fi
}

check_relro() {
	local relro=$(readelf -l "$BINARY" 2>/dev/null | grep "GNU_RELRO" | wc -l)
	if [ "$relro" -gt 0 ]; then
		local full_relro=$(readelf -d "$BINARY" 2>/dev/null | grep "BIND_NOW" | wc -l)
		if [ "$full_relro" -gt 0 ]; then
			echo "[+] RELRO: FULL"
		else
			echo "[+] RELRO: PARTIAL"
		fi
	else
		echo "[+] RELRO: NONE"
	fi
}

check_canary() {
	local canary=$(readelf -s "$BINARY" 2>/dev/null | grep -c "stack_chk_fail")
	if [ "$canary" -gt 0 ]; then
		echo "[+] CANARY: ENABLED"
	else
		echo "[+] CANARY: DISABLED"
	fi
}

check_nx
check_pie
check_relro
check_canary

echo ""
echo "[*] For detailed analysis, use:"
echo "    checksec --file=$BINARY"
echo "    or pwntools: python -c 'from pwn import *; elf=ELF(\"$BINARY\"); print(elf.checksec())'"
