# Cryptography Tools

Essential CTF cryptography attack scripts and utilities for breaking classical ciphers and RSA.

## Quick Start

### Setup
```bash
uv pip install pycryptodome sympy
```

### Running Scripts
```bash
# Classical cipher attacks
python classic/caesar.py "ciphertext"
python classic/vigenere.py -c "ciphertext" -w wordlist.txt
python classic/frequency_analysis.py "ciphertext"
python classic/xor_single_byte.py "hexstring"
python classic/xor_repeating_key.py "hexstring" -k keysize

# RSA attacks
python rsa_tool/small_e.py -e 3 -n modulus -c ciphertext
python rsa_tool/common_modulus.py -c1 c1 -c2 c2 -n1 n1 -n2 n2
python rsa_tool/wiener.py -e exponent -n modulus
python rsa_tool/fermat.py -n modulus
```

## Directory Structure

### `/classic/` - Classical Cipher Attacks
Breaking traditional ciphers using frequency analysis and known-plaintext recovery.

| Script | Purpose | Attack |
|--------|---------|--------|
| `caesar.py` | Brute-force Caesar cipher | Frequency scoring |
| `vigenere.py` | Break Vigenere cipher | Kasiski examination + frequency |
| `frequency_analysis.py` | Analyze cipher text frequencies | English letter distribution |
| `xor_single_byte.py` | Recover single-byte XOR key | Brute force + frequency |
| `xor_repeating_key.py` | Recover repeating-key XOR | Hamming distance key length estimation |

### `/rsa_tool/` - RSA Attack Suite
Fast factorization and decryption exploits for weak RSA implementations.

| Script | Purpose | Vulnerability |
|--------|---------|---|
| `rsa_common.py` | Helper functions (gcd, egcd, crt, iroot, etc.) | Utility module |
| `small_e.py` | Decrypt small public exponent (e=3,5,17) | Small e + small plaintext |
| `common_modulus.py` | Recover message from two ciphertexts same n | Reused modulus with different exponents |
| `wiener.py` | Recover private key from large d | Wiener's continued fraction attack |
| `fermat.py` | Factor RSA modulus | Fermat factorization (n with close factors) |

## Common Workflows

### Identify Cipher Type
```bash
# Check if ciphertext only contains 0-9 and A-F → likely XOR
# Check if ciphertext is long alphanumeric → Caesar or Vigenere
# Use frequency analysis to confirm polyalphabetic cipher

python classic/frequency_analysis.py "ciphertext"
```

### Break Caesar Cipher
```bash
python classic/caesar.py "KHOOR ZRUOG"
# Output: ROT shift with highest frequency match
```

### Break Vigenere (known plaintext)
```bash
python classic/vigenere.py -c "CIPHERTEXT" -w common_words.txt -p "known plaintext fragment"
```

### XOR with Unknown Key Length
```bash
python classic/xor_repeating_key.py "48656c6c6f"
# Tries key lengths 1-32, finds most likely plaintext
```

### RSA with Small e
```bash
python rsa_tool/small_e.py -e 3 -n 221 -c 142
# For m^3 < n, directly computes m = cbrt(c)
```

### RSA with Common Modulus Attack
```bash
python rsa_tool/common_modulus.py \
  -c1 12345 -e1 17 \
  -c2 67890 -e2 19 \
  -n 260753
```

## External Tools & References

### Online Tools
- **CyberChef**: Fast cipher analysis and XOR operations
  - URL: https://gchq.github.io/CyberChef/
  - Use for quick frequency analysis and XOR visualization

### Standalone Tools
- **RsaCtfTool**: Comprehensive RSA attack suite
  ```bash
  git clone https://github.com/RanSommer/RsaCtfTool.git
  cd RsaCtfTool
  pip install -r requirements.txt
  python3 RsaCtfTool.py --publickey key.pub --uncipher ciphertext
  ```

- **FactorDB**: Online factorization database
  - URL: http://factordb.com/
  - Check if large RSA modulus already factored

### Python Libraries Used
- `pycryptodome`: AES, RSA, SHA, random primitives
- `sympy`: Integer factorization, math utilities

## Algorithm Notes

### Caesar Cipher
- **Time**: O(26 × n) for n ciphertext length
- **Key space**: 26 possible shifts
- **Break**: Try all 26 rotations, score by English letter frequency

### Vigenere Cipher
- **Key length recovery**: Kasiski examination (repeating sequences)
- **Break**: Find key length, reduce to Caesar for each position
- **Wordlist attack**: Try common words as key

### XOR Cipher
- **Single-byte XOR**: O(256 × n) brute force
- **Repeating-key XOR**: 
  - Find key length via Hamming distance (Kasiski variation)
  - Solve single-byte XOR for each key byte

### RSA Attacks

**Small e Attack** (e = 3, 5, ...)
- If m^e < n, simply: m = ∛(c)
- Typical for lazy CTF challenges

**Common Modulus Attack** (same n, different e)
- Use extended GCD to find a, b where ae + be' = gcd(e, e')
- Recover m = c^a × c'^b (mod n)

**Wiener Attack**
- Recover d from continued fraction expansion of e/n
- Works when d < n^0.25
- Time: O(log² n)

**Fermat Factorization**
- Find factors if they're close: n = p × q where p ≈ q
- Try n = a² - b² to find (a-b) and (a+b)
- Time: O(√(n/4)) iterations

## CTF Tips

1. **Always try Wiener first** for RSA if no obvious weak point
2. **Check FactorDB** before implementing factorization
3. **Frequency analysis beats brute force** for classical ciphers
4. **XOR is common in CTFs** - always check plaintext hypothesis
5. **Save wordlists** - reuse common.txt, rockyou.txt patterns
6. **Use CyberChef for quick validation** before scripting

## Dependencies

Install with:
```bash
uv pip install pycryptodome sympy
```

Or from project root:
```bash
uv pip install -e .
```

## Script Development Notes

- All scripts use `argparse` for CLI flexibility
- Assume input ciphertext in hex unless specified
- Output plaintext attempts ranked by confidence
- No external API calls (fully offline)
- Fast implementations prioritized over academic correctness
