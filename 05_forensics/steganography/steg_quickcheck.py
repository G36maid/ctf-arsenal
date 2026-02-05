#!/usr/bin/env python3
"""
Steganography Quick Check - Try common extraction methods on images.

Usage:
    python steg_quickcheck.py <image_file>

Tries:
    - steghide extraction (common in CTF)
    - stegoveritas analysis
    - zsteg for PNG/GIF
    - exiftool metadata
    - strings extraction
"""

import sys
import subprocess
import os


def run_command(cmd, description):
    """Run command and print results."""
    print(f"\n[*] {description}")
    print(f"    Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode == 0 and result.stdout:
            # Print first 500 chars of output
            output = result.stdout.decode("utf-8", errors="ignore")[:500]
            print(f"    Output:\n{output}")
            return True
        else:
            stderr = result.stderr.decode("utf-8", errors="ignore")[:200]
            if stderr:
                print(f"    Error: {stderr}")
    except subprocess.TimeoutExpired:
        print(f"    Timeout (>10s)")
    except FileNotFoundError:
        print(
            f"    Tool not found - install with: apt install {cmd[0]} or pip install {cmd[0]}"
        )
    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python steg_quickcheck.py <image_file>")
        sys.exit(1)

    image_file = sys.argv[1]

    if not os.path.exists(image_file):
        print(f"[-] File not found: {image_file}")
        sys.exit(1)

    print(f"[*] Steganography Quick Check: {image_file}\n")
    print("=" * 60)

    # Try common extraction methods
    methods = [
        (["file", image_file], "1. File type identification"),
        (["exiftool", image_file], "2. Metadata extraction (EXIF, IPTC, XMP)"),
        (["strings", image_file], "3. Strings extraction"),
        (
            [
                "steghide",
                "extract",
                "-sf",
                image_file,
                "-p",
                "",
                "-xf",
                "/tmp/steg_extract.bin",
            ],
            "4. Steghide extraction (no password)",
        ),
        (["zsteg", image_file], "5. PNG/GIF steganography (zsteg)"),
        (
            ["stegoveritas", image_file, "-out", "/tmp/stegoveritas_out"],
            "6. Stegoveritas full analysis",
        ),
    ]

    found_hidden = False

    for cmd, desc in methods:
        if run_command(cmd, desc):
            found_hidden = True

    print("\n" + "=" * 60)

    # Check if steghide extracted anything
    if os.path.exists("/tmp/steg_extract.bin"):
        size = os.path.getsize("/tmp/steg_extract.bin")
        if size > 0:
            print(f"\n[+] Steghide extraction successful! ({size} bytes)")
            print(f"    File: /tmp/steg_extract.bin")
            found_hidden = True

    # Check stegoveritas output
    if os.path.exists("/tmp/stegoveritas_out"):
        print(f"\n[+] Stegoveritas analysis complete")
        print(f"    Output directory: /tmp/stegoveritas_out")
        found_hidden = True

    if not found_hidden:
        print("\n[!] No obvious hidden data found")
        print("    Suggestions:")
        print(
            "    - Try steghide with a wordlist: steghide extract -sf <file> -p <password>"
        )
        print("    - Check LSB manually: stegoveritas -b <file>")
        print("    - Examine hex dump for magic bytes: xxd <file> | head -50")


if __name__ == "__main__":
    main()
