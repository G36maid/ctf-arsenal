#!/bin/bash
# Audio Spectrogram Generator
# Purpose: Generate spectrograms from audio files for frequency analysis
# Usage:
#     ./spectrogram.sh audio.wav
#     ./spectrogram.sh audio.wav output.png
#     ./spectrogram.sh -batch *.mp3

set -e

# Check if sox is installed
if ! command -v sox &>/dev/null; then
	echo "[!] sox not found. Install with: sudo apt-get install sox"
	exit 1
fi

# Function to generate spectrogram
generate_spec() {
	local input="$1"
	local output="$2"

	if [ ! -f "$input" ]; then
		echo "[!] File not found: $input"
		return 1
	fi

	# Default output filename
	if [ -z "$output" ]; then
		output="${input%.*}_spectrogram.png"
	fi

	echo "[*] Generating spectrogram: $input -> $output"

	# Generate spectrogram using sox
	sox "$input" -n spectrogram -o "$output" -X 200 -Y 200 2>/dev/null

	if [ $? -eq 0 ]; then
		echo "[+] Spectrogram saved: $output"
		return 0
	else
		echo "[!] Failed to generate spectrogram"
		return 1
	fi
}

# Main
if [ $# -eq 0 ]; then
	echo "Usage: $0 <audio_file> [output.png]"
	echo "       $0 -batch *.mp3"
	echo ""
	echo "Examples:"
	echo "  $0 audio.wav                          # Output: audio_spectrogram.png"
	echo "  $0 audio.wav custom_output.png        # Custom output filename"
	echo "  $0 -batch *.mp3                       # Batch process multiple files"
	exit 1
fi

# Batch mode
if [ "$1" = "-batch" ]; then
	shift
	count=0
	success=0
	for file in "$@"; do
		if generate_spec "$file"; then
			((success++))
		fi
		((count++))
	done
	echo ""
	echo "[*] Summary: Processed $count files, success: $success"
	exit 0
fi

# Single file mode
input="$1"
output="${2:-}"

generate_spec "$input" "$output"
