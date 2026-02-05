# PlayShaMiGame CTF Challenge - Complete Analysis

## Challenge Overview
Text-based RPG game where you fight a "Corrupted AI". Goal is to get shell access.

## Files
- `game_server.bin` - Downloaded ELF binary (from product_id=0)
- `solve.py` - Basic special skill exploit attempt
- `solve_legit.py` - Legitimate gameplay path
- `ANALYSIS.md` - Detailed reverse engineering notes

## Binary Analysis Summary

### Key Functions

1. **`cast_special_skillv()` (0x401476)**
   - Reads up to 0x200 bytes of input
   - Converts to number with `atoll()`
   - Calculates: `result = input^2 * 3`
   - Compares with magic value: `0xb5f72f1ded389973`
   - If equal: throws "Crystal Overload!" exception

2. **`wish_ultimate_powerv()` (0x402102)**
   - Displays "Admin panel accessed. But nothing is here."
   - Catches "Crystal Overload!" exception
   - On exception: prints "Something went wrong" → "Entering debug mode" → calls `system("/bin/sh")`

3. **`grant_wishesv()` (0x401cb3)**  
   - Called after defeating AI
   - Offers 3 wishes
   - Option 2 calls `wish_ultimate_power()`

### The Vulnerability

The magic comparison value `0xb5f72f1ded389973` has **no integer solution**:
```python
# Need: x^2 * 3 = 0xb5f72f1ded389973
# Solution: x ≈ 2090613996.389 (not an integer!)
```

This appears intentionally impossible, suggesting alternate paths.

### Exploitation Strategies

#### Strategy 1: Legitimate Gameplay (RECOMMENDED)
1. Attack the AI repeatedly (option 1)
2. Win the game
3. Choose wish option 2 ("Ultimate Power")
4. Function somehow triggers the exception → spawns shell

**Implementation**: `solve_legit.py`

#### Strategy 2: Buffer Overflow (DIFFICULT)
- Buffer at `[rbp-0x110]`, result at `[rbp-0x118]`
- Result is BEFORE buffer in memory → cannot overflow forward
- `atoll()` stops at non-digits → limits injection
- Stack canary present

#### Strategy 3: Integer Overflow (TESTED - FAILED)
- Tested values near INT64_MAX/MIN
- No wraparound produces the magic value

## Download URLs

```bash
# Game binary (ELF)
curl http://192.168.100.121:30021/download?product_id=0 -o game_server.bin

# Challenge description
curl http://192.168.100.121:30021/download?product_id=2

# product_id=1 requires token (payment bypass - failed)
```

## Running the Exploit

```bash
# When instance is active:
python3 solve_legit.py 192.168.100.121 40021
```

## Next Steps
- [ ] Test solve_legit.py against live instance
- [ ] If that fails, investigate exception handling flow more deeply
- [ ] Consider alternate triggers for the exception

## Technical Notes

- Binary: x86-64 ELF, dynamically linked, not stripped
- Stack canary: enabled
- NX: enabled  
- PIE: disabled
- C++ exceptions used for control flow (unusual in CTF)
