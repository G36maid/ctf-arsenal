#!/usr/bin/env python3
from pwn import *
import re

firmwares = {
    "R0n": "./csc2025/GrounTruth/bomb.R0n.ino.elf",
    "Asn": "./csc2025/GrounTruth/bomb.Asn.ino.elf",
    "R0s": "./csc2025/GrounTruth/bomb.R0s.ino.elf",
    "Ass": "./csc2025/GrounTruth/bomb.Ass.ino.elf",
    "Rss": "./csc2025/GrounTruth/bomb.Rss.ino.elf",
}


def analyze_firmware(name, path):
    print(f"\n{'=' * 60}")
    print(f"Analyzing: {name} - {path}")
    print(f"{'=' * 60}")

    try:
        elf = ELF(path, checksec=False)
        print(f"Architecture: {elf.arch}")
        print(f"Bits: {elf.bits}")

        with open(path, "rb") as f:
            data = f.read()

        strings = re.findall(b"[ -~]{4,}", data)
        print(f"Found {len(strings)} strings")

        gpio_keywords = [
            b"gpio",
            b"GPIO",
            b"pin",
            b"PIN",
            b"wire",
            b"WIRE",
            b"digital",
            b"DIGITAL",
            b"analog",
            b"ANALOG",
            b"port",
            b"PORT",
            b"IO",
            b"RP2040",
        ]

        print(f"\nGPIO-related strings:")
        print("-" * 60)
        found_gpio = False
        for s in sorted(set(strings)):
            if any(kw in s for kw in gpio_keywords):
                print(f"  {s.decode('utf-8', errors='ignore')}")
                found_gpio = True

        if not found_gpio:
            print("  (None found)")

        print(f"\nPotential GPIO numbers (0-30):")
        print("-" * 60)
        pin_numbers = set()
        for s in strings:
            numbers = re.findall(
                r"\b([0-9]|[1-2][0-9]|30)\b", s.decode("utf-8", errors="ignore")
            )
            for num in numbers:
                pin_numbers.add(int(num))

        if pin_numbers:
            for pin in sorted(pin_numbers):
                print(f"  GPIO {pin}")
        else:
            print("  (None found)")

        print(f"\nSymbols:")
        print("-" * 60)
        if elf.symbols:
            for name, addr in elf.symbols.items():
                if any(
                    kw.lower() in name.lower()
                    for kw in ["gpio", "pin", "wire", "digital"]
                ):
                    print(f"  {hex(addr)}: {name}")

        return elf

    except Exception as e:
        print(f"Error analyzing {path}: {e}")
        return None


results = {}
for name, path in firmwares.items():
    results[name] = analyze_firmware(name, path)

print(f"\n\n{'=' * 60}")
print("SUMMARY")
print(f"{'=' * 60}")
print(f"Key findings:")
print("- bomb.R0n.ino.elf (RISC-V, not stripped) - Most complete for analysis")
print("- bomb.Asn.ino.elf (ARM, not stripped) - Alternative architecture")
print(f"\nHints from challenge:")
print("- Left-top corner is GPIO 8")
print("- Right-top corner is GPIO 0")
print("- Need to find pin <-> internal calculation mapping")
print("- Look for GPIO operations")
