# Forensics Toolkit

Quick reference for forensic analysis in CTF competitions.

## Directory Structure

- **file_analysis/**: Binary file examination, file carving, magic bytes
- **steganography/**: Steg detection and extraction
- **network_forensics/**: PCAP analysis, traffic extraction
- **helpers/**: Utility scripts for entropy, metadata, etc.

## Quick Triage Workflow

### 1. File Type & Metadata
```bash
# Check magic bytes and basic info
file suspicious.bin
binwalk suspicious.bin                          # Detect embedded files
strings suspicious.bin | head -50               # Look for readable strings
exiftool image.jpg                              # Extract metadata
```

### 2. Entropy Scan (Possible Compression/Encryption)
```bash
python helpers/entropy_scan.py suspicious.bin
# Output: Entropy levels indicate data type
```

### 3. Steganography Check
```bash
python steganography/steg_quickcheck.py image.png
# Try common steg formats and extraction methods
```

### 4. PCAP Analysis
```bash
# Quick HTTP extraction
python network_forensics/pcap_extract_http.py traffic.pcap

# Or use tshark directly
tshark -r traffic.pcap -Y "http.request" -T fields -e http.request.uri
```

### 5. File Carving & Extraction
```bash
# Extract embedded files
bash file_analysis/binwalk_extract.sh suspicious.bin

# Manual carving with hex editor or dd
# Look for magic bytes: 89504e47 (PNG), ffd8ff (JPEG), 504b0304 (ZIP)
```

## Common Tools

### File Analysis
- `file` - Determine file type
- `binwalk` - Detect and extract embedded files
- `strings` - Extract readable ASCII strings
- `hexdump` / `xxd` - Hex dump inspection
- `exiftool` - Extract metadata from images/documents

### Steganography
- `steghide` - Hide/extract data in images/audio
- `stegoveritas` - Multi-format steg detection
- `outguess` - LSB steganography
- `pngcheck` - PNG analysis
- `zsteg` - PNG/GIF steg detection

### Network Forensics
- `tshark` - Command-line Wireshark alternative
- `tcpdump` - Packet capture and filtering
- `scapy` - Python packet manipulation (see 02_ics_traffic/)
- `NetworkMiner` - Automated PCAP analysis (GUI alternative: `wireshark`)

### Memory & System
- `volatility3` - Memory forensics framework
- `grep` / `strings` - Text search in binaries

## Common Challenges

### Encrypted/Compressed Data
- High entropy indicates compression or encryption
- Try common passwords with tools like `hashcat`, `john`
- Check for ZIP/RAR/7z magic bytes

### Hidden Data
- LSB steganography in images (use `stegoveritas`, `zsteg`)
- Metadata in images (use `exiftool`)
- Slack space in files (use `binwalk`, `foremost`)

### Network Traces
- Extract HTTP payloads: `tshark -r file.pcap -Y "http.response.body" -T fields`
- Reassemble TCP streams: `tcpflow -r file.pcap -C`
- Look for DNS queries: `tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name`

## Notes

- **Overlap with 02_ics_traffic**: PCAP analysis uses same tools (scapy, tshark)
- **Volatility3**: For memory dumps, requires profile identification first
- **Always preserve originals**: Work on copies of evidence files
- **Document findings**: Keep notes of commands run and results

## Resources

- Volatility3: `https://volatilityfoundation.org/`
- Binwalk: `https://github.com/ReFirmLabs/binwalk`
- Stegoveritas: `https://github.com/bannsec/stegoVeritas`
