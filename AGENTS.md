# AGENTS.md - CTF Arsenal Agent Guide

## Project Overview

CTF Arsenal is a toolkit for security competitions (Capture The Flag). Contains templates, tools, and scripts for binary exploitation, web security, ICS/SCADA attacks, cryptography, and forensics.

**Project Type**: CTF utility scripts and exploit templates (NOT a standard software project)
**Primary Language**: Python 3.10+
**Key Focus**: Speed and pragmatism over strict engineering discipline

---

## Build/Install Commands

### Environment Setup

**IMPORTANT**: This project uses `uv` for Python package management (faster than pip, modern Rust-based).

```bash
# Setup Python virtual environment with uv
uv venv
source .venv/bin/activate  # or use .venv/bin/activate in fish shells

# Install project dependencies using uv
uv pip install pwntools requests beautifulsoup4 pycryptodome

# Or install from pyproject.toml
uv pip install -e .
```

### Running Scripts
```bash
# Standard Python scripts
python script.py
# Or with uv
uv run python script.py

# Scapy scripts (requires root)
sudo python scapy_script.py

# Ettercap (requires root)
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/

# Pwn templates support three modes
python solve.py                  # Local
python solve.py GDB              # Debug
python solve.py REMOTE IP PORT   # Remote
# Or with uv:
# uv run python solve.py GDB
# uv run python solve.py REMOTE IP PORT
```

### System Tools Setup
```bash
# GDB configuration
cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit

# Enable IP forwarding (required for MITM attacks)
sudo sysctl -w net.ipv4.ip_forward=1

# Ruby gems PATH (for one_gadget, seccomp-tools)
source scripts/setup_gem_path.sh  # Temporary
# Or add to ~/.zshrc for permanent:
# export PATH="$HOME/.local/share/gem/ruby/3.4.0/bin:$PATH"
```

### Testing
**No formal test suite.** Manual verification only:
```bash
# Test pwn template works
python 00_templates/pwn_basic.py

# Or with uv:
# uv run python 00_templates/pwn_basic.py

# Verify dependencies
python -c "from pwn import *; print('OK')"
python -c "import requests; print('OK')"
```

---

## Code Style Guidelines

### Python Script Structure

```python
#!/usr/bin/env python3
"""
Purpose: Brief description
Usage:
    python script.py [args]
"""

# Imports - standard library first, then third-party
import sys
from pwn import *
import requests

# Constants/Configuration
HOST = "localhost"
PORT = 8080

# Helper functions (if needed)
def helper_func(arg):
    """Docstring describing purpose."""
    return arg

# Main execution
def main():
    # Code here
    pass

if __name__ == "__main__":
    main()
```

### Imports

- **Standard practice**: Use wildcard imports for pwntools (`from pwn import *`)
- **Standard library**: Group at top, separate from third-party
- **Order**: stdlib → third-party → local modules

```python
# ✅ Preferred
from pwn import *
import requests
import sys

# ❌ Avoid in production, but acceptable in CTF
from scapy.all import *
```

### Naming Conventions

- **Functions/Variables**: `snake_case`
- **Constants**: `UPPER_CASE`
- **Classes**: `PascalCase` (rarely needed)
- **Files**: `snake_case.py` for utilities, `category_name.py` for challenges

```python
# ✅ Good
exploit_payload = b'A' * 72
BUFFER_SIZE = 1024
def calculate_offset():
    pass

# ❌ Bad
payload = b'AAAA'
def CalculateOffset():
    pass
```

### Pwntools Patterns

Templates in `00_templates/` demonstrate standard patterns:

```python
# Binary setup
exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

# Auto-switch start function
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
```

### Payload Construction

Use pwntools `flat()` for structured payloads:

```python
# ✅ Good - clear structure
payload = flat({
    offset: [
        pop_rdi,
        elf.got["puts"],
        elf.plt["puts"],
        elf.symbols["main"]
    ]
})

# Acceptable for simple cases
payload = b'A' * offset + rop_chain
```

### Web Scripts

Use `requests.Session()` for persistent connections:

```python
import requests
from bs4 import BeautifulSoup

session = requests.Session()

# Disable SSL warnings in CTF environments
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Proxy for Burp Suite
proxies = {"http": "http://127.0.0.1:8080"}
```

### Error Handling

**Minimal error handling is acceptable** in CTF scripts. Focus on getting the flag:

```python
# ✅ Good for CTF - simple and direct
try:
    io = remote(host, port)
    io.recvuntil(b"flag{")
    flag = io.recvuntil(b"}").decode()
    print(f"[+] Flag: {flag}")
except Exception as e:
    print(f"[-] Error: {e}")

# No need for extensive logging or graceful degradation
```

### Comments

- **English** for code comments when possible
- **Chinese** acceptable in templates for quick CTF reference
- **Docstrings** for helper functions

```python
# ✅ Good - concise
# Calculate buffer overflow offset
offset = cyclic_find(core.rsp)

# Template pattern (Chinese OK in CTF)
# ===== Stage 1: 資訊洩漏 =====
```

### File Organization

```
00_templates/      # Starter templates (COPY & MODIFY)
01_bin_exploit/    # Binary exploitation tools
02_ics_traffic/    # ICS/SCADA scripts (Ettercap, Scapy)
03_web/            # Web exploitation
04_crypto/         # Cryptography tools
05_forensics/      # Forensics
06_misc/           # Miscellaneous
cheat_sheets/      # Quick reference guides
scripts/           # Setup scripts
static_bins/       # Static binaries for offline use
```

---

## Special Considerations

### Root Privileges

Some scripts **require root**:
- Scapy (packet manipulation)
- Ettercap (MITM attacks)
- Network sniffing

```bash
# ✅ Correct
sudo python scapy_script.py

# ❌ Will fail
python scapy_script.py
```

### Python Version

Use `#!/usr/bin/env python3` shebang. Minimum Python 3.10.

### Dependencies Management

**Use `uv` for all Python package management.** Do NOT add dependencies to pyproject.toml unless necessary.
This is a lightweight toolkit, not a full application.

**Core dependencies** (already in pyproject.toml):
- `pwntools>=4.12.0`
- `requests>=2.31.0`
- `beautifulsoup4>=4.12.0`
- `pycryptodome>=3.19.0`

**Install new packages:**
```bash
uv pip install package_name
```

### GDB Configuration

Use pwndbg as default (most common in CTF):

```bash
# Set up pwndbg
echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit
```

GDB script pattern for templates:

```python
gdbscript = """
init-gef  # or pwndbg auto-loads
b *main+123
continue
""".format(**locals())
```

### No Type Hints

Type hints are **optional and rarely used** in CTF scripts. Focus on speed and clarity.

```python
# ✅ Acceptable
def exploit(offset: int, payload: bytes) -> None:
    pass

# ✅ Also acceptable (more common)
def exploit(offset, payload):
    pass
```

---

## Workflow Guidelines

### Creating New Exploit Scripts

1. **Copy from templates**: Always start from `00_templates/`
2. **Modify minimally**: Only change what's needed for the challenge
3. **Test locally first**: Run without `REMOTE` flag
4. **Add GDB script** if debugging is needed
5. **Keep it simple**: Don't over-engineer

### Adding New Tools

1. Place in appropriate category directory (01-06)
2. Add shebang and brief docstring
3. Test with sample inputs if possible
4. Update README if it's a core tool

### Documentation

- **Cheat sheets** go in `cheat_sheets/` (quick reference)
- **Technical docs** go in `docs/` (detailed information)
- Keep README concise, defer details to docs/

---

## Anti-Patterns (Avoid These)

- ❌ **Don't** add type hints or strict linting to CTF exploit scripts
- ❌ **Don't** create abstract classes or complex OOP for simple exploits
- ❌ **Don't** add extensive logging (pwntools context is enough)
- ❌ **Don't** use `async` unless necessary (adds complexity)
- ❌ **Don't** create tests for one-off exploit scripts

---

## Quick Reference

### Pwntools Quick Commands
```python
cyclic(500)              # Generate pattern
cyclic_find(b'caaa')     # Find offset
flat({...})              # Build structured payload
u64(data.ljust(8, b'\x00'))  # Unpack bytes to int
p64(0x401000)            # Pack int to bytes
gdb.debug(...)           # Launch with GDB
remote(host, port)       # Connect to remote
process([...])           # Run local process
```

### Common Scapy Patterns
```python
from scapy.all import *

sniff(filter="tcp port 502", prn=callback, store=0)
IP(dst=target)/TCP(dport=port)/Raw(load=payload)
```

### Web Request Patterns
```python
session.get(url, proxies=proxies, verify=False)
session.post(url, data=data, files=files)
soup = BeautifulSoup(response.text, 'html.parser')
```

---

## Important Notes for Agents

1. **This is CTF context, not production software**: Pragmatism > Engineering discipline
2. **Templates are starting points**: Copy and modify, don't import as modules
3. **Speed matters**: Get the flag, not perfect code
4. **No formal tests**: Manual verification only
5. **Comments over documentation**: In-activity files, comments are more valuable
6. **Keep files self-contained**: Don't create complex module hierarchies for one-off scripts

---

**Remember**: This toolkit is for 5-hour competition sprints, not long-term maintenance. Optimize for speed and clarity over architecture and patterns.
