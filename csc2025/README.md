# CSC 2025 - 金盾獎 CTF 解題記錄

2025 年資安競賽金盾獎（csc2025）的解題記錄與整理。

## 競賽資訊

- **競賽名稱**: CSC 2025 金盾獎
- **競賽時間**: 2025 年 1 月
- **參賽形式**: CTF (Capture The Flag)

## 題目總覽

| 題目 | 類型 | 難度 | 狀態 | 關鍵技術 |
|------|------|------|------|----------|
| [AbyssPhantonTeam](./AbyssPhantonTeam/) | Rev + Crypto | ⭐⭐⭐ | ✅ | Z3 Solver, AES CBC |
| [bank](./bank/) | Web + Crypto | ⭐⭐⭐⭐ | ✅ | LFI, hashcat, bcrypt |
| [Gold-Doc](./Gold-Doc/) | Web | ⭐⭐⭐ | ✅ | XSS, Path Traversal, Agent Manipulation |
| [GrounTruth](./GrounTruth/) | Rev + Hardware | ⭐⭐⭐⭐ | ✅ | Arduino, Double SHA512, RISC-V |
| [llm-this](./llm-this/) | Rev | ⭐⭐⭐ | ✅ | strace, Anti-LLM, UPX |
| [PlayShaMiGame](./PlayShaMiGame/) | Pwn | ⭐⭐⭐⭐ | ❌ | C++ Exception, Binary Exploitation |
| [score-sys](./score-sys/) | Web | ⭐⭐⭐ | ✅ | SQL Injection, PyInstaller RE |
| [timespy](./timespy/) | Crypto + Rev | ⭐⭐⭐ | ✅ | RC4, Go RE, GDB |

**總計**: 8 題，7 題已解，1 題未解

## 統一目錄結構

每個題目都遵循以下標準結構：

```
題目名稱/
├── README.md           # 題目說明、解題思路、關鍵技術
├── challenge/          # 原始題目檔案
├── solution/           # 解題腳本
├── decompile/          # 反編譯結果（如適用）
├── tools/              # 輔助工具（如適用）
├── docs/               # 詳細文檔（如適用）
└── archive/            # 失敗嘗試、臨時檔案
```

## 解題技術統計

### 類型分布
- **Web**: 3 題 (bank, Gold-Doc, score-sys)
- **Reverse Engineering**: 4 題 (AbyssPhantonTeam, GrounTruth, llm-this, timespy)
- **Pwn**: 1 題 (PlayShaMiGame)
- **Crypto**: 3 題交叉 (AbyssPhantonTeam, bank, timespy)

### 關鍵技術
- **密碼學**: RC4, AES CBC, bcrypt, Double SHA512
- **逆向工程**: Z3 Solver, Ghidra, IDA, GDB, strace
- **Web 漏洞**: SQL Injection, XSS, Path Traversal, LFI
- **工具**: hashcat, PyInstaller, UPX, Arduino

## 快速開始

### 查看特定題目
```bash
cd csc2025/題目名稱
cat README.md
```

### 執行解題腳本
```bash
cd csc2025/題目名稱/solution
python solve.py
```

## 學習心得

### 成功題目的共通點
1. **動態分析優於靜態分析**: llm-this, timespy 都需要動態調試
2. **工具鏈熟練度**: hashcat, GDB, Ghidra 的熟練運用
3. **多層漏洞鏈**: Gold-Doc, bank 需要組合多個漏洞

### 未解題目的挑戰
- **PlayShaMiGame**: 數學上不可能的觸發條件，可能需要非預期解

## 工具清單

本次競賽使用的主要工具：

### 逆向工程
- Ghidra
- IDA Pro
- GDB + pwndbg/peda
- strace/ltrace
- objdump
- UPX

### Web 安全
- Burp Suite
- Python + requests
- hashcat

### 密碼學
- Python + pycryptodome
- Python + z3-solver
- hashcat

### 硬體分析
- Arduino IDE
- pyOCD / OpenOCD

## 檔案說明

### challenge/
包含原始題目檔案，通常包括：
- 二進位可執行檔
- 題目說明文件
- 題目附件（如資料庫、配置檔等）

### solution/
包含最終工作的解題腳本，通常命名為 `solve.py`

### decompile/
包含靜態分析的反編譯結果：
- Ghidra 反編譯的 C 程式碼
- objdump 反組譯輸出
- IDA 分析結果

### archive/
包含解題過程中的失敗嘗試、中間版本、臨時檔案。這些檔案保留用於：
- 學習參考（了解錯誤路徑）
- 複習解題過程
- 未來研究

## 參考資源

### CTF 平台
- CTFtime: https://ctftime.org/
- PicoCTF: https://picoctf.org/

### 學習資源
- CTF Wiki: https://ctf-wiki.org/
- Awesome CTF: https://github.com/apsdehal/awesome-ctf
- LiveOverflow: https://www.youtube.com/c/LiveOverflow

### 工具文檔
- Ghidra: https://ghidra-sre.org/
- pwntools: https://docs.pwntools.com/
- hashcat: https://hashcat.net/hashcat/

## 貢獻

本倉庫是個人學習記錄，歡迎交流討論。

## 授權

個人學習與研究用途。題目版權歸 CSC 2025 主辦方所有。
