# PlayShaMiGame CTF Challenge Analysis

## Challenge Info
- Website: http://192.168.100.121:30021
- Game Server: 192.168.100.121:40021
- Binary downloaded from: http://192.168.100.121:30021/download?product_id=0

## Binary Analysis

### Key Functions
1. `cast_special_skillv()` - Special Skill option in game
   - Reads user input (up to 0x200 bytes) 
   - Converts to long long with `atoll()`
   - Calculates: `result = input^2 * 3`
   - Compares with magic value: `0xb5f72f1ded389973`
   - If equal: throws "Crystal Overload!" exception

2. `wish_ultimate_powerv()` - Wish option after defeating AI
   - Catches "Crystal Overload!" exception
   - Calls `system("/bin/sh")` when exception caught

### The Problem
Magic value `0xb5f72f1ded389973` has no integer solution for `x^2 * 3 = target`
- Calculated closest: x = 2090613996.389
- This appears to be an impossible condition

### Exploitation Strategies to Explore
1. **Buffer Overflow**: read() accepts 0x200 bytes into buffer at [rbp-0x110]
   - Stack canary present (`__stack_chk_fail`)
   - Need to analyze if we can overwrite comparison result at [rbp-0x118]
   - Problem: atoll() stops at non-digits, limiting overflow techniques

2. **Integer Overflow**: Large inputs might wrap around
   - Tested values near INT64_MAX - no matches found

3. **Alternative Path**: Win the game legitimately, choose wish option 2
   - Need to actually defeat the AI in combat
   - Then choose "wish_ultimate_power" option

4. **Format String/Injection**: Check if input parsing has other vulns

## Next Steps
- [ ] Test legitimate game winning path
- [ ] Analyze exact stack layout for overflow possibility 
- [ ] Check for other input validation issues
- [ ] Consider web download bypass (product_id manipulation already tested)
