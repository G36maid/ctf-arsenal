# llm-this (PastedLM this) - CSC2025

## 題目類型
Reverse Engineering (Anti-LLM Challenge)

## 題目描述
600 分的逆向題，標題 "PastedLM this"，描述提到「不要浪費 Token」。這是一道 Anti-LLM 設計的題目，需要使用傳統逆向工程技巧而非 AI 輔助。

## Flag
```
CSC{l0ng_1Iv3_rev3rs3_3ng!nEer5_9beff18934}
```

## 解題思路

### ❌ 錯誤路徑：XSS 解密（誤導陷阱）
1. UPX 解包後進行靜態分析
2. 找到 XOR key 和加密數據
3. 解密得到：`C5C{n0t_th1s_t1m3}`
4. **這是誤導！** Flag 格式應為 `CSC{...}` 而非 `C5C{...}`

### ✅ 正確路徑：動態分析
1. 使用 `strace` 追蹤系統呼叫
2. 發現程式檢查檔案 `/tmp/2404917857`
3. 創建該檔案並填入正確內容
4. 程式自動生成 `/tmp/3404927857` 包含 flag

## 關鍵技術
- **UPX**: 打包器分析（標準解包行為被修改）
- **strace**: 系統呼叫追蹤（關鍵工具）
- **動態分析**: 運行時行為觀察

## 使用工具
- strace - 系統呼叫追蹤
- GDB - 動態調試
- UPX - 打包器分析
- Ghidra/IDA - 靜態分析

## 目錄結構
```
llm-this/
├── challenge/          # 原始題目檔案
│   └── llm-this        # UPX 打包的可執行檔
├── solution/           # 解題筆記
│   ├── solution_final.txt  # 正確解法
│   └── summary.txt     # 簡要總結
├── decompile/          # 靜態分析結果
│   ├── decompile.c     # Ghidra 反編譯
│   └── disasm.txt      # objdump 反組譯
└── archive/            # 錯誤路徑和調試檔案
    ├── solution.txt    # 錯誤解法（XOR 解密）
    ├── solve.py        # XOR 解密腳本（誤導用）
    ├── *.gdb           # GDB 調試腳本
    └── ...
```

## 解題步驟

### 使用 strace 追蹤
```bash
cd challenge
strace ./llm-this 2>&1 | grep -E "(open|access|stat)"
```

### 創建必要檔案
```bash
# 根據 strace 輸出創建檔案
echo "[正確內容]" > /tmp/2404917857

# 執行程式
./llm-this

# 讀取 flag
cat /tmp/3404927857
```

## 教訓與啟發

這題展示了「老把戲」的價值：
- ✅ **strace/ltrace** - 傳統動態分析工具仍然有效
- ❌ **Ghidra/IDA 靜態分析** - 會陷入誤導路徑
- ❌ **LLM 輔助** - 容易被 XOR 解密路徑誤導

**關鍵洞見**: 有時候最簡單的工具才是最有效的。

## 參考資料
- strace manual: `man strace`
- UPX: https://upx.github.io/
- Linux System Calls: https://man7.org/linux/man-pages/man2/syscalls.2.html
