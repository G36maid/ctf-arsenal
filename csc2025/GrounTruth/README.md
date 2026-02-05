# GrounTruth - CSC2025

## 題目類型
Reverse Engineering + Hardware (Arduino Firmware)

## 題目描述
拆除 Arduino 裝置上的炸彈，需要根據 EEPROM 中的 seed 計算正確的剪線順序。

## Flag
```
flag{21個字符}
```

## 解題思路

### 1. 固件分析
- 使用 Ghidra/IDA 分析 RISC-V 架構的 Arduino 固件
- 發現使用 Double SHA512 演算法決定剪線順序
- 從 EEPROM 讀取 5 bytes seed (位址 2-6)

### 2. 演算法還原
- 固件使用 Double SHA512(seed + pin_number) 計算每條線的雜湊值
- 根據雜湊值排序決定 16 條線的剪線順序
- 必須按照 rank 1 → 2 → ... → 16 的順序剪線

### 3. 自動化解題
- 從裝置 OLED 顯示讀取 seed（10 hex 字符）
- 使用 Python 腳本計算正確的剪線順序
- 執行剪線操作取得 flag

## 關鍵技術
- **逆向工程**: RISC-V 架構分析
- **密碼學**: Double SHA512
- **硬體操作**: Arduino GPIO 控制

## 使用工具
- Ghidra (RISC-V 反編譯)
- Python + hashlib
- Arduino Serial Monitor

## 目錄結構
```
GrounTruth/
├── challenge/          # 原始題目檔案
│   ├── bomb.ino        # Arduino 原始碼
│   ├── bomb.R0n.ino.elf  # RISC-V 未 stripped 固件（最佳分析目標）
│   └── flash_dump.bin  # EEPROM dump
├── solution/           # 解題腳本
│   ├── defuse_pi.py    # 互動式拆彈工具（推薦）
│   └── solve.py        # 基礎解題腳本
├── tools/              # 分析工具
│   ├── analyze_firmware.py  # 固件分析
│   └── analyze_pins.py      # Pin 計算器
├── docs/               # 文檔
│   ├── FINAL_GUIDE.md       # 完整使用指南
│   └── COMPLETE_DEFUSE_GUIDE.md  # 技術細節
├── decompile/          # 反編譯結果
│   └── bomb.R0n.ino.elf.c
└── archive/            # 其他版本和測試檔案
```

## 解題步驟

### 使用互動式工具（推薦）
```bash
cd solution
python defuse_pi.py

# 輸入從裝置 OLED 顯示的 Seed（10 個 hex 字符）
# 例如：2dcf462904
```

### 手動計算剪線順序
```bash
cd tools
python analyze_pins.py <seed>
```

## 演算法說明
```python
import hashlib

def calculate_rank(seed_bytes, pin):
    # 第一次 SHA512
    hash1 = hashlib.sha512(seed_bytes + bytes([pin])).digest()
    # 第二次 SHA512 (Double SHA512)
    hash2 = hashlib.sha512(hash1).digest()
    # 取前 8 bytes 作為 rank
    return int.from_bytes(hash2[:8], 'little')

# 計算所有 16 條線的 rank
ranks = [(pin, calculate_rank(seed, pin)) for pin in range(16)]
# 排序後得到剪線順序
sorted_pins = sorted(ranks, key=lambda x: x[1])
```

## 硬體資訊
- **架構**: RISC-V (RP2040/Pico)
- **總 Pin 數**: 16 (4x4 matrix)
- **EEPROM**: 使用位址 2-6 儲存 5 bytes seed

## 參考資料
- Double SHA512: https://en.bitcoin.it/wiki/Protocol_documentation#Hashes
- RISC-V: https://riscv.org/
- RP2040: https://www.raspberrypi.com/documentation/microcontrollers/rp2040.html
