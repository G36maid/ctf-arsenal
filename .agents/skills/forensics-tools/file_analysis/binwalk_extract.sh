#!/bin/bash
#
# Binwalk Automated Extraction - Detect and extract embedded files from binary.
#
# Usage:
#     bash binwalk_extract.sh <file> [output_dir]
#
# Extracts:
#     - Compressed archives (ZIP, GZIP, BZIP2, 7Z, RAR)
#     - Filesystem images (ext2/3/4, JFFS2, squashfs)
#     - Firmware images (uImage, device tree, rootfs)
#     - Media files (JPEG, PNG, etc)
#

set -e

FILE="${1:-.}"
OUTPUT_DIR="${2:-.}"

if [ ! -f "$FILE" ]; then
	echo "[-] File not found: $FILE"
	exit 1
fi

echo "[*] Binwalk Extraction: $FILE"
echo "[*] Output directory: $OUTPUT_DIR"
echo "============================================================"

# Check if binwalk is installed
if ! command -v binwalk &>/dev/null; then
	echo "[-] binwalk not found"
	echo "    Install: apt install binwalk"
	exit 1
fi

# Scan for signatures
echo ""
echo "[*] Stage 1: Signature Scan"
binwalk "$FILE" | head -20

# Extract with output directory
echo ""
echo "[*] Stage 2: Extracting files..."
binwalk -e -d 5 "$FILE" --directory "$OUTPUT_DIR" 2>/dev/null || {
	echo "[-] Extraction failed, trying without depth limit..."
	binwalk -e "$FILE" --directory "$OUTPUT_DIR"
}

# List extracted files
echo ""
echo "[+] Extraction complete!"
if [ -d "$OUTPUT_DIR" ]; then
	echo "[*] Found files:"
	find "$OUTPUT_DIR" -type f | head -20

	# Calculate extracted size
	SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
	echo "[*] Total extracted: $SIZE"

	# Quick analysis hints
	echo ""
	echo "[*] Next steps:"
	echo "    1. Look for filesystem images: file $OUTPUT_DIR/*"
	echo "    2. Mount filesystem: mkdir /tmp/mnt && mount $OUTPUT_DIR/..._filesystem /tmp/mnt"
	echo "    3. Extract strings: strings $OUTPUT_DIR/* | grep -i flag"
	echo "    4. Check for shell scripts: find $OUTPUT_DIR -name '*.sh' -o -name '*.py'"
fi

echo "============================================================"
