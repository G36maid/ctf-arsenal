# Ghidra 練習範例

這是一個用於練習 Ghidra + GDB 逆向工程的測試專案，不屬於任何 CTF 競賽題目。

## 內容

- **test** - 測試用的 ELF 二進位檔案（密碼檢查程式）
- **test.c** - 原始碼
- **crack_summary.md** - 使用 GDB + GEF 破解的完整步驟
- **mySecondGhidra.gpr** - Ghidra 專案檔
- **mySecondGhidra.rep/** - Ghidra 專案資料庫

## 破解目標

找出硬編碼的密碼：**Secret123** ✓

## 使用的工具

- GDB + GEF/pwndbg
- Ghidra
- 靜態分析 + 動態調試
