# timespy - CSC2025

## 題目類型
Crypto + Reverse Engineering (RC4 + Go binary)

## 題目描述
Go 編譯的靜態連結二進位，使用 RC4 加密 flag，需要從記憶體中提取密鑰進行解密。

## Flag
```
CSC{st34l1nG_71m3_b1d8e38a29}
```

## 解題思路

### 1. 靜態分析
- Go 二進位包含完整 debug info（not stripped）
- 發現使用 RC4 對稱加密
- 加密 flag 儲存在二進位中

### 2. 動態調試
- 使用 GDB 設置斷點在 RC4 初始化函數
- 從記憶體中提取 RC4 密鑰
- 記錄加密 flag 的位置

### 3. 解密 Flag
- 使用提取的密鑰和加密 flag 進行 RC4 解密
- Python 實作 RC4 演算法
- 取得明文 flag

## 關鍵技術
- **Go Reverse Engineering**: Go 二進位分析
- **Cryptography**: RC4 stream cipher
- **Dynamic Analysis**: GDB 記憶體提取

## 使用工具
- GDB - 動態調試
- Ghidra/IDA - 靜態分析
- Python + hashlib

## 目錄結構
```
timespy/
├── challenge/          # 原始題目檔案
│   ├── timespy         # Go 編譯的二進位
│   └── flag.txt        # Flag
├── solution/           # 解題腳本
│   └── solve.py        # RC4 解密腳本
├── decompile/          # 反編譯結果
│   └── decompile.c     # Ghidra 反編譯
└── archive/            # GDB 調試檔案
    ├── gdb_extract_key.txt
    ├── gdb_script.py
    ├── key_extract.log
    └── ...
```

## 解題步驟

### 使用 GDB 提取密鑰
```bash
cd challenge
gdb ./timespy

# 設置斷點
break *[RC4_init_address]
run

# 檢查記憶體
x/32xb [key_address]
x/32xb [encrypted_flag_address]
```

### 解密 Flag
```bash
cd solution
python solve.py
```

## RC4 演算法說明

RC4 是一種流加密演算法：
1. 使用密鑰初始化 256 byte 的狀態陣列（S-box）
2. 生成偽隨機位元流
3. 將密文與位元流 XOR 得到明文

## 檔案資訊

- **Binary**: ELF 64-bit LSB executable, statically linked, with debug_info, not stripped
- **Size**: 7.9MB
- **Language**: Go (Golang)

## 參考資料
- RC4: https://en.wikipedia.org/wiki/RC4
- Go Reverse Engineering: https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/
- GDB Manual: https://sourceware.org/gdb/current/onlinedocs/gdb/
