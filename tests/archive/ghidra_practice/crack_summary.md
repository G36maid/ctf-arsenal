# Cracking Test ELF with GDB + GEF

## Target Analysis
- **Binary**: test (ELF 64-bit, PIE enabled, not stripped)
- **Challenge**: Password checker comparing user input to hardcoded password

## Cracking Steps with GDB + GEF

### 1. Initial Analysis
```bash
file test
# Output: ELF 64-bit LSB pie executable, x86-64
```

### 2. Disassembly Analysis
Key instructions found:
```asm
<main+17>:  movabs rax, 0x3231746572636553   # Load first 8 bytes into RAX
<main+21>:  mov    QWORD PTR [rbp-0x2a], rax # Store to stack
<main+25>:  mov    WORD PTR [rbp-0x22], 0x33 # Store last byte '3' (0x33)
```

### 3. Password Extraction via GDB
Set breakpoint after password is stored in memory:
```gdb
b *main+43
run
x/s $rbp-0x2a    # Examine string at password location
```

**Result**: `0x7fffffffe266: "Secret123"`

### 4. Decoding the Password
- Hex value `0x3231746572636553` = "Secret12" (little-endian)
- Plus `0x33` = '3'
- **Full password**: `Secret123`

### 5. Verification
```bash
echo "Secret123" | ./test
# Output: Correct!
```

## GEF Features Used
- **Automatic context display**: Registers, stack, code view
- **Color-coded output**: Easy to identify different memory regions
- **Python integration**: Direct hex-to-string conversion
- **Memory examination**: `x/s`, `x/c` commands for string inspection

## Key Techniques
1. **Static analysis**: Disassembly to locate password loading instructions
2. **Dynamic analysis**: Breakpoint at password storage location
3. **Memory inspection**: Direct memory read from stack location
4. **Verification**: Test extracted password against binary

## Password Found
**`Secret123`** ✓
