# PlayShaMiGame - CSC2025

## 題目類型
Pwn (Binary Exploitation)

## 題目描述
文字 RPG 遊戲的二進位程式，需要找到漏洞繞過遊戲邏輯取得 flag。

## 狀態
❌ **未解題**

## 嘗試過的攻擊向量

### 1. 正常遊玩路徑
- 嘗試透過正常遊戲流程達成觸發條件
- **結果**: 數學上無法達成（`x² × 3 = 0xb5f72f1ded389973` 無整數解）

### 2. Buffer Overflow
- 嘗試溢出緩衝區覆蓋返回地址
- **結果**: 被 stack canary 阻擋

### 3. Integer Overflow
- 嘗試利用整數溢出達成觸發條件
- **結果**: 無法找到匹配的溢出值

### 4. Exception Carryover
- 嘗試讓 C++ 例外跨函數傳遞
- **結果**: 例外處理機制無法繞過

## 關鍵技術
- **Binary Exploitation**: Buffer Overflow, Integer Overflow
- **C++ Reverse Engineering**: Exception handling
- **Dynamic Analysis**: GDB debugging

## 使用工具
- GDB + pwntools
- Ghidra/IDA
- Python exploit scripts

## 目錄結構
```
PlayShaMiGame/
├── challenge/          # 原始題目檔案
│   ├── game_server.bin # 題目二進位
│   ├── game_server     # 題目說明
│   ├── token           # Flag token（未成功取得）
│   └── challenge_description.md
├── solution/           # 解題嘗試
│   └── solve.py        # 最接近成功的腳本
├── docs/               # 分析文檔
│   ├── README.md       # 完整分析
│   └── FINAL_STATUS.md # 最終狀態（UNSOLVED）
└── archive/            # 其他嘗試
    ├── exploit.py
    ├── exploit_exception_carry.py
    ├── exploit_special.py
    └── ...
```

## 失敗原因總結

1. **數學不可能**: 觸發條件 `x² × 3 = 0xb5f72f1ded389973` 在整數域無解
2. **例外處理不可達**: Exception handler 無法透過正常遊戲流程觸發
3. **多重防護**: Stack canary, ASLR, NX 等防護機制

## 學習心得

雖然未能解題，但過程中學到：
- 複雜的 C++ 例外處理機制
- 多層防護的繞過策略思考
- 動態分析與靜態分析的結合運用

## 參考資料
- C++ Exception Handling: https://en.cppreference.com/w/cpp/language/exceptions
- Stack Canary: https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries
