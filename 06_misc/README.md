# 06_misc - Miscellaneous CTF Tools

Toolkit for OSINT, programming puzzles, esoteric languages, QR/barcodes, and audio/video forensics.

## Categories

### 📍 OSINT (`osint/`)
Open Source Intelligence reconnaissance and enumeration.

**Quick one-liners:**
```bash
# Username enumeration (sherlock)
sherlock username

# Domain enumeration
whois domain.com
dig domain.com

# Email enumeration
holehe email@example.com

# GitHub enumeration
ghorg user

# Shodan API search
shodan search "port:22"
```

**OSINT Checklist:**
- [ ] Username searches (sherlock, whatsmyname)
- [ ] Domain/IP WHOIS lookups
- [ ] DNS enumeration (dig, nslookup, dnsdumpster)
- [ ] Email reputation (holehe, haveibeenpwned)
- [ ] GitHub repository scanning
- [ ] Social media profiles (Google, Facebook, LinkedIn, Twitter)
- [ ] Geolocation from metadata (exiftool)
- [ ] Public code repositories (GitHub, GitLab, Bitbucket)
- [ ] Shodan/Censys searches
- [ ] Certificate transparency logs (crt.sh)

### 💻 Programming (`programming/`)
Programming puzzles, quick parsers, and parsing templates.

**Quick one-liners:**
```bash
# JSON parsing
jq '.field' file.json

# CSV parsing
awk -F',' '{print $1}' file.csv

# Binary data
xxd -r -p hex.txt > binary.bin

# Base64
echo "data" | base64 -d

# URL encoding/decoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"
```

### 🔮 Esoteric Languages (`esolang/`)
Interpreters and decoders for unusual programming languages.

**Includes:**
- Brainfuck interpreter (`bf_decode.py`)

**Quick one-liners:**
```bash
# Brainfuck execution
python3 bf_decode.py code.bf

# Whitespace esolang
wsf input.ws

# Shakespeare programming language
spl2c code.spl
```

### 📱 QR/Barcodes (`qr_barcodes/`)
QR code and barcode scanning and generation.

**Quick one-liners:**
```bash
# Scan all QR codes from image
zbarimg image.png

# Generate QR code
qrencode -o qr.png "text"

# Scan from camera
zbarcam

# Batch scan
for img in *.png; do zbarimg "$img"; done
```

### 🎵 Audio/Video (`audio_video/`)
Audio forensics, spectrograms, metadata extraction.

**Quick one-liners:**
```bash
# Generate spectrogram
spectrogram audio.wav

# Extract metadata
ffprobe -show_format audio.wav

# Audio to hex
xxd -p audio.mp3 | head -c 200

# Metadata with exiftool
exiftool video.mp4

# Frequency analysis (sox)
sox audio.wav -n spectrogram -o spec.png
```

## Installation

### System Tools
```bash
# OSINT tools
sudo apt-get install -y whois dnsutils sherlock holehe

# QR/Barcode scanning
sudo apt-get install -y zbar-tools qrencode

# Audio/Video
sudo apt-get install -y sox ffmpeg exiftool

# General utilities
sudo apt-get install -y jq python3-PIL
```

### Python Dependencies
```bash
uv pip install pycryptodome requests beautifulsoup4
```

## Usage

Each subdirectory contains focused tools for its category. Scripts are self-contained and executable:

```bash
# Brainfuck interpreter
python3 esolang/bf_decode.py code.bf

# QR scanning
./qr_barcodes/qr_scan_all.sh *.png

# Spectrogram generation
./audio_video/spectrogram.sh audio.wav
```

## Notes

- All scripts use standard CTF libraries (pwntools, requests, beautifulsoup4)
- Focus on speed and single-purpose tools
- Keep scripts standalone (copy-and-modify, don't import)
- Minimal dependencies for portability
