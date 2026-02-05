# Ground Truth - CTF Challenge Analysis

## Challenge Overview
Reverse engineer Arduino firmware to defuse a "bomb" by cutting wires in the correct order.

## Key Findings

### 1. Pin Mapping (`check_pins[16]` array)
Found in firmware binary at offset `0x22e48`:

```
Logical Pin  0 -> GPIO  8  (LEFT-TOP)
Logical Pin  1 -> GPIO  9
Logical Pin  2 -> GPIO 10
Logical Pin  3 -> GPIO 11
Logical Pin  4 -> GPIO 12
Logical Pin  5 -> GPIO 13
Logical Pin  6 -> GPIO 14
Logical Pin  7 -> GPIO 15
Logical Pin  8 -> GPIO  0  (RIGHT-TOP)
Logical Pin  9 -> GPIO 22
Logical Pin 10 -> GPIO 21
Logical Pin 11 -> GPIO 20
Logical Pin 12 -> GPIO 19
Logical Pin 13 -> GPIO 18
Logical Pin 14 -> GPIO 17
Logical Pin 15 -> GPIO 16
```

### 2. Pin Ranking Algorithm (`calculate_pins_order`)

The firmware uses **Double SHA512** to calculate the cutting order:

```python
def calculate_pins_order(seed_string):
    # Step 1: Double SHA512 hash
    first_hash = sha512(seed_string)
    second_hash = sha512(first_hash)
    
    # Step 2: Count bits for each pin
    pins_order = [0] * 16
    for j in range(64):  # 64 bytes in hash
        for i in range(8):  # 8 bits per byte
            if (second_hash[j] >> i) & 1:
                idx = (j * 8 + i) % 16
                pins_order[idx] += 1
    
    # Step 3: Sort and assign ranks (1-16)
    # Higher bit count = Lower rank = Cut earlier
    # Rank 1 = Cut FIRST
    # Rank 16 = Cut LAST
    
    return pins_order  # Array of ranks [1-16]
```

### 3. Game Logic (`check_disconn` function)

```
1. Each wire (pin) has a "rank" value (1-16)
2. When a wire is cut (LOW -> HIGH):
   - If rank == 1: CORRECT! Decrease all other pins' ranks by 1
   - If rank != 1: WRONG! EXPLODE!
3. When all ranks become 0: WIN! Display flag
```

## Solving Strategy

### Step 1: Get the Seed
- Read EEPROM addresses 2-6 (5 bytes)
- Convert to 10-character hex string (e.g., "a1b2c3d4e5")
- Seed is displayed on device as "S/N: xxxxx..."

### Step 2: Calculate Cutting Order
Use `solve.py` script:
```bash
cd csc2025/GrounTruth
python3 solve.py
# Enter seed when prompted
```

### Step 3: Cut Wires
Follow the calculated cutting order:
- Cut wires in the sequence shown (rank 1 first)
- After each cut, remaining pins' ranks decrease by 1
- All ranks 0 = WIN = FLAG!

## Files

- `bomb.R0n.ino.elf` - RISC-V firmware (not stripped, best for analysis)
- `solve.py` - Complete solution script
- `analyze_pins.py` - Pin order calculator with examples

## Example Output

With seed "deadbeef01":

```
Step   Rank   Logical  GPIO Pin   Position
------------------------------------------------------------
1      1      2        10         
2      2      6        14         
3      3      7        15         
4      4      3        11         
5      5      9        22         
6      6      4        12         
7      7      12       19         
8      8      0        8          (LEFT-TOP)
...
16     16     15       16
```

## Hints from Challenge

1. **Left-top corner is GPIO 8** → Logical Pin 0
2. **Right-top corner is GPIO 0** → Logical Pin 8
3. **Find pin <-> internal calculation mapping** → check_pins array
4. **Need to cut in rank order** → calculate_pins_order function

## Technical Details

- **Architecture**: RISC-V 32-bit (RP2040/Pico)
- **Hash**: Double SHA512 (seed → hash → hash again)
- **GPIO Range**: 0-30 (valid pins)
- **Total Pins**: 16 (4x4 matrix arrangement)
- **Win Condition**: All pins cut with correct sequence

## Quick Reference

```bash
# Run solution
python3 solve.py

# Manual calculation
python3 analyze_pins.py
```

## Success Criteria

- Read seed from EEPROM or device display
- Calculate pin rankings using algorithm
- Cut wires in correct order (rank 1 → 2 → ... → 16)
- See flag displayed on screen (21 characters)
