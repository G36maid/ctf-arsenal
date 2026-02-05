# ⚠️ DEPRECATED

This directory has been moved to the OpenCode skills structure.

## New Location

All pwn templates are now in:

```
.agents/skills/pwn-exploits/templates/
```

## Quick Migration

```bash
# Old way
cp 00_templates/pwn_basic.py solve.py

# New way
cp .agents/skills/pwn-exploits/templates/pwn_basic.py solve.py
```

## Available Templates

- `pwn_basic.py` - Basic buffer overflow with auto-switch (local/GDB/remote)
- `pwn_rop.py` - ROP chain template with ret2libc pattern
- `pwn_format_string.py` - Format string exploitation
- `angr_template.py` - Symbolic execution with angr
- And more...

## Documentation

See `.agents/skills/pwn-exploits/SKILL.md` for comprehensive documentation.

---

**This directory will be removed in a future update. Please update your scripts and bookmarks.**
