# CTF Arsenal Skills

OpenCode-compatible skills for CTF (Capture The Flag) competitions. Each skill provides specialized tools, templates, and workflows for different challenge categories.

---

## Available Skills

| Skill | Category | Description | Trigger Keywords |
|-------|----------|-------------|------------------|
| [pwn-exploits](pwn-exploits/) | Binary Exploitation | Buffer overflows, ROP chains, shellcode, format strings, heap exploitation with pwntools | `pwn`, `binary`, `exploit`, `overflow`, `rop`, `shellcode`, `pwntools`, `ret2libc` |
| [web-exploits](web-exploits/) | Web Security | SQL injection, XSS, CSRF, LFI/RFI, SSTI, file upload bypass, deserialization | `web`, `sqli`, `xss`, `lfi`, `ssti`, `csrf`, `upload`, `injection` |
| [ics-traffic](ics-traffic/) | ICS/SCADA | Modbus, IEC 104, DNP3 protocol analysis, Ettercap MITM, Scapy packet crafting | `ics`, `scada`, `modbus`, `iec104`, `dnp3`, `mitm`, `ettercap`, `industrial` |
| [crypto-tools](crypto-tools/) | Cryptography | RSA attacks (small e, Wiener, Fermat), classical ciphers, XOR analysis | `crypto`, `rsa`, `cipher`, `xor`, `caesar`, `vigenere`, `encryption` |
| [forensics-tools](forensics-tools/) | Digital Forensics | File carving, steganography, PCAP analysis, entropy scanning, metadata extraction | `forensics`, `steg`, `pcap`, `binwalk`, `file carving`, `metadata`, `hidden data` |
| [misc-tools](misc-tools/) | Miscellaneous | Esoteric languages (Brainfuck), QR/barcodes, audio spectrograms, video analysis | `misc`, `brainfuck`, `qr`, `barcode`, `spectrogram`, `audio`, `esolang` |

---

## Usage

### For OpenCode Agents

Skills are automatically discovered from this directory. Load skills using the skill tool:

```typescript
// Load a specific skill
skill({ name: "pwn-exploits" })

// Skills are then available in agent context
```

### For Human Users

Each skill directory contains:

```
skill-name/
├── SKILL.md          # Main skill definition with workflows
├── tools/            # Helper scripts and utilities
├── templates/        # Starter templates for competitions
├── references/       # Documentation and cheat sheets
└── [resources]       # Payloads, wordlists, etc.
```

**Quick Start Example (Binary Exploitation):**

```bash
# Copy template to start exploit development
cp .agents/skills/pwn-exploits/templates/pwn_basic.py solve.py

# Edit solve.py and run
python solve.py              # Local testing
python solve.py GDB          # Debug with GDB
python solve.py REMOTE IP PORT  # Remote attack
```

---

## Skill Structure Philosophy

**CTF Context = Speed Over Architecture**

These skills are designed for **5-hour competition sprints**, not long-term software projects:

- ✅ **Self-contained scripts**: Copy templates and modify directly
- ✅ **Pragmatic patterns**: Speed and clarity over strict engineering
- ✅ **Minimal dependencies**: Core tools only (pwntools, requests, scapy)
- ✅ **Quick reference**: Inline comments and cheat sheets
- ❌ **No complex modules**: Don't create abstract class hierarchies
- ❌ **No extensive tests**: Manual verification only
- ❌ **No type hints**: Optional and rarely used

---

## Dependencies

### Core Python Packages

Managed with `uv` (modern Rust-based package manager):

```bash
# Setup environment
uv venv
source .venv/bin/activate

# Install core dependencies
uv pip install pwntools requests beautifulsoup4 pycryptodome
```

### System Tools (Platform-Specific)

```bash
# Binary exploitation
sudo apt install gdb gdb-peda  # or pwndbg, gef

# Forensics
sudo apt install binwalk foremost volatility

# ICS/SCADA
sudo apt install ettercap-text-only scapy

# Cryptography
gem install one_gadget
pip install pycryptodome gmpy2

# Web
burpsuite (GUI), sqlmap, feroxbuster
```

---

## Environment Setup

### Python Virtual Environment

```bash
cd /path/to/ctf-arsenal
uv venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate  # Windows
```

### GDB Configuration (Recommended)

```bash
# Use pwndbg (most common in CTF)
echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit

# Or copy pre-configured versions
cp .agents/skills/pwn-exploits/gdb_init/gdbinit-pwndbg ~/.gdbinit
```

### Network Configuration (for ICS/SCADA)

```bash
# Enable IP forwarding (MITM attacks)
sudo sysctl -w net.ipv4.ip_forward=1

# Persistent (add to /etc/sysctl.conf)
net.ipv4.ip_forward=1
```

---

## Workflow Patterns

### 1. Binary Exploitation Workflow

```bash
# Step 1: Static analysis
strings ./vuln | grep -iE "flag|key"
python .agents/skills/pwn-exploits/decompile.py ./vuln  # Batch decompile

# Step 2: Dynamic analysis (understand before exploiting)
cp .agents/skills/pwn-exploits/templates/pwn_basic.py solve.py
python solve.py GDB

# Step 3: Exploit development
# Edit solve.py with findings from static/dynamic analysis

# Step 4: Remote exploitation
python solve.py REMOTE ctf.example.com 1337
```

### 2. Web Exploitation Workflow

```bash
# Step 1: Reconnaissance
# Use browser + Burp Suite to understand application

# Step 2: Identify vulnerability
python .agents/skills/web-exploits/lfi_tester.py http://target/page?file=

# Step 3: Exploit development
# Modify scripts or use payloads from web-exploits/payloads/

# Step 4: Flag extraction
curl -X POST http://target/login --data "@.agents/skills/web-exploits/payloads/sqli/auth_bypass.txt"
```

### 3. ICS/SCADA Workflow

```bash
# Step 1: Network reconnaissance
sudo nmap -p 502,2404,20000 --script modbus-discover target

# Step 2: Traffic analysis
sudo python .agents/skills/ics-traffic/scapy_scripts/modbus_sniffer.py

# Step 3: MITM attack
sudo ettercap -T -i eth0 -F .agents/skills/ics-traffic/mitm_scripts/modbus_filter.etter -M arp:remote /target/ /gateway/
```

---

## Quick Reference

### Common Commands by Skill

| Skill | Common Commands |
|-------|-----------------|
| **pwn-exploits** | `checksec`, `ROPgadget`, `one_gadget`, `gdb`, `cyclic`, `objdump` |
| **web-exploits** | `burpsuite`, `sqlmap`, `ffuf`, `curl`, `wfuzz`, `nikto` |
| **ics-traffic** | `nmap --script modbus-*`, `ettercap`, `scapy`, `wireshark` |
| **crypto-tools** | `openssl`, `python -c "..."`, `RsaCtfTool`, `hashcat` |
| **forensics-tools** | `binwalk`, `foremost`, `strings`, `exiftool`, `volatility` |
| **misc-tools** | `zbarimg` (QR), `sox` (audio), `ffmpeg` (video), `python` |

### Pwntools Quick Reference

```python
from pwn import *

# Pattern generation/offset
cyclic(500)
cyclic_find(b'caaa')

# Payload construction
payload = flat({offset: [rop_chain]})

# Packing/unpacking
u64(leak.ljust(8, b'\x00'))
p64(address)

# Process interaction
io = remote(host, port)
io.sendline(payload)
io.recvuntil(b"flag{")
```

---

## File Organization

```
.agents/skills/
├── README.md                    # This file
├── pwn-exploits/
│   ├── SKILL.md                 # Skill definition
│   ├── templates/               # Pwn starter templates
│   ├── tools/                   # checksec, offset_finder, etc.
│   ├── gadgets/                 # ROPgadget scripts
│   ├── gdb_init/                # GDB configuration
│   └── references/              # Cheat sheets
├── web-exploits/
│   ├── SKILL.md
│   ├── payloads/                # SQLi, XSS, SSTI payloads
│   ├── webshells/               # PHP, ASPX, JSP shells
│   └── wordlists/               # Fuzzing wordlists
├── ics-traffic/
│   ├── SKILL.md
│   ├── scapy_scripts/           # Packet crafting
│   ├── mitm_scripts/            # Ettercap filters
│   └── protocol_docs/           # Protocol references
├── crypto-tools/
│   ├── SKILL.md
│   ├── rsa_tool/                # RSA attack scripts
│   └── classic/                 # Classical ciphers
├── forensics-tools/
│   ├── SKILL.md
│   ├── file_analysis/           # Binwalk, carving
│   ├── steganography/           # Steg tools
│   └── network_forensics/       # PCAP analysis
└── misc-tools/
    ├── SKILL.md
    ├── esolang/                 # Brainfuck decoder
    ├── qr_barcodes/             # QR/barcode tools
    ├── audio_video/             # Spectrogram analysis
    └── programming/             # Parsing helpers
```

---

## Anti-Patterns (Avoid These)

CTF scripts are **NOT production software**. Avoid:

- ❌ **Complex OOP architectures** for simple exploits
- ❌ **Type hints everywhere** (optional in CTF context)
- ❌ **Extensive error handling** (get the flag, not perfect code)
- ❌ **Abstract base classes** for one-off scripts
- ❌ **Unit tests** for exploit scripts (manual verification)
- ❌ **Async/await** unless truly necessary (adds complexity)
- ❌ **Over-engineering** (KISS principle in competitions)

**Remember**: Optimize for competition speed, not long-term maintenance.

---

## Contributing

When adding new tools:

1. Place in appropriate skill directory
2. Add shebang (`#!/usr/bin/env python3`) and brief docstring
3. Update skill's SKILL.md if it's a significant tool
4. Test with sample inputs if possible
5. Keep it simple and self-contained

**Don't**: Create complex module hierarchies or require new dependencies without discussion.

---

## Important Notes for OpenCode Agents

1. **Context is CTF, not production**: Pragmatism > strict engineering discipline
2. **Templates are starting points**: Copy and modify, don't import as modules
3. **Speed matters**: Get the flag in 5 hours, not perfect architecture
4. **No formal tests**: Manual verification only
5. **Root privileges**: Some scripts require `sudo` (Scapy, Ettercap, packet sniffing)
6. **Python 3.10+**: Minimum version required
7. **Use `uv` for packages**: Modern package manager, not `pip` directly

---

## License

Various licenses apply to different components. See individual skill directories and tool files for specific licensing information.

Most tools are MIT or GPL-licensed for CTF educational purposes.

---

## Resources

- **Project Repository**: <https://github.com/your-org/ctf-arsenal> (update link)
- **OpenCode Documentation**: <https://opencode.ai/docs/skills/>
- **CTF Resources**: See individual skill SKILL.md files for curated links

---

**Last Updated**: 2026-02-06  
**OpenCode Skills Version**: 1.0.0
