# AbyssPhantonTeam - CSC2025

## 題目類型
Reverse Engineering + Cryptography

## 題目描述
Windows PE 可執行檔逆向分析，需要破解密碼驗證邏輯並解密 AES 加密的 flag。

## Flag
```
cschahaha
```

## 解題思路

### 1. 靜態分析
- 使用 Ghidra/IDA 反編譯 `ghost_decrypted.exe`
- 提取密碼驗證函數的約束條件（28+ 個條件）

### 2. 密碼破解
- 使用 Z3 SMT 求解器解決複雜的密碼約束條件
- 最終密碼：`CSC2025PASSWORD`（儲存在 `challenge/password.txt`）

### 3. Flag 解密
- 使用密碼解密 AES CBC 加密的 flag
- 執行：`python solution/decrypt_flag.py`

## 關鍵技術
- **逆向工程**: Ghidra/IDA Pro 反編譯
- **約束求解**: Z3 SMT Solver
- **密碼學**: AES CBC 解密

## 使用工具
- Ghidra
- Python + z3-solver
- pycryptodome

## 目錄結構
```
AbyssPhantonTeam/
├── challenge/          # 原始題目檔案
│   ├── APT_cschahaha.zip
│   ├── password.txt    # 最終密碼
│   └── dist/           # 題目二進位檔案
├── solution/           # 解題腳本
│   ├── solve.py        # Z3 求解器
│   └── decrypt_flag.py # Flag 解密
├── decompile/          # 反編譯結果
│   ├── c8763.exe.c
│   └── ghost_decrypted.exe.c
└── archive/            # 失敗嘗試（學習參考）
    ├── bruteforce.py
    ├── solve_password.py
    └── ...
```

## 解題步驟
```bash
# 1. 使用 Z3 求解密碼約束
cd solution
python solve.py

# 2. 使用密碼解密 flag
python decrypt_flag.py
```

## 參考資料
- Z3 Solver: https://github.com/Z3Prover/z3
- AES CBC Mode: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
