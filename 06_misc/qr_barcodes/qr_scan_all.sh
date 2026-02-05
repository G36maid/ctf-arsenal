#!/bin/bash
# QR/Barcode Scanner - Batch
# Purpose: Scan all QR codes and barcodes from image files
# Usage:
#     ./qr_scan_all.sh *.png
#     ./qr_scan_all.sh image.jpg
#     ./qr_scan_all.sh -d directory/

set -e

# Check if zbarimg is installed
if ! command -v zbarimg &>/dev/null; then
	echo "[!] zbarimg not found. Install with: sudo apt-get install zbar-tools"
	exit 1
fi

# Function to scan single file
scan_file() {
	local file="$1"

	if [ ! -f "$file" ]; then
		echo "[!] File not found: $file"
		return 1
	fi

	# Check if file is an image
	if ! file "$file" | grep -qE "(image|PNG|JPEG|GIF)"; then
		echo "[!] Not an image file: $file"
		return 1
	fi

	echo "[*] Scanning: $file"

	# Scan with zbarimg
	result=$(zbarimg "$file" 2>/dev/null || echo "")

	if [ -z "$result" ]; then
		echo "    [!] No QR/barcodes found"
		return 1
	else
		echo "$result" | while read -r line; do
			echo "    [+] $line"
		done
	fi
}

# Main
if [ $# -eq 0 ]; then
	echo "Usage: $0 [image_files...] or -d [directory]"
	echo "Example: $0 *.png"
	echo "Example: $0 -d ./images/"
	exit 1
fi

# Directory mode
if [ "$1" = "-d" ] && [ -n "$2" ]; then
	if [ ! -d "$2" ]; then
		echo "[!] Directory not found: $2"
		exit 1
	fi
	echo "[*] Scanning directory: $2"
	count=0
	found=0
	for file in "$2"/*; do
		if scan_file "$file"; then
			((found++))
		fi
		((count++))
	done
	echo ""
	echo "[*] Summary: Scanned $count files, found QR/barcodes in $found files"
	exit 0
fi

# File mode
count=0
found=0
for file in "$@"; do
	if scan_file "$file"; then
		((found++))
	fi
	((count++))
done

echo ""
echo "[*] Summary: Scanned $count files, found QR/barcodes in $found files"
