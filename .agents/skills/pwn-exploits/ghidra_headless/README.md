# Ghidra Headless Decompile

使用 Ghidra headless 模式批次反編譯二進制檔案的工具和腳本。

## 快速開始

### 一鍵執行

```bash
# 基本用法
./decompile_headless.sh /path/to/binary output.c

# 指定 Ghidra 路徑
GHIDRA_PATH=/opt/ghidra ./decompile_headless.sh binary output.c
```

### 手動執行

```bash
# 1. 複製腳本到工作目錄
mkdir -p my_project/ghidra_scripts
cp DecompileCLI.java my_project/ghidra_scripts/

# 2. 執行 Ghidra headless
cd my_project
/opt/ghidra/support/analyzeHeadless \
    ./ghidra_project \
    MyProject \
    -import ./target_binary \
    -scriptPath ./ghidra_scripts \
    -postScript DecompileCLI.java \
    -deleteProject \
    2>/dev/null | grep -v "^INFO\|^WARN\|^ERROR" \
    > decompile.c
```

## 腳本說明

### DecompileCLI.java

Ghidra Java 腳本，用於反編譯所有函數並輸出到標準輸出。

**功能**:
- 遍歷二進制檔案中的所有函數
- 使用 Ghidra Decompiler 反編譯每個函數
- 輸出格式化的 C 代碼

**相容性**:
- Ghidra 10.x, 11.x, 12.x
- 支援所有 Ghidra 支援的架構 (x86, x86-64, ARM, MIPS, etc.)

### decompile_headless.sh

Bash wrapper 腳本，簡化 Ghidra headless 的使用。

**功能**:
- 自動檢測 Ghidra 安裝路徑
- 建立臨時工作目錄
- 過濾 Ghidra 日誌輸出
- 錯誤處理和清理

## 使用範例

### 範例 1: 反編譯 ELF 二進制

```bash
./decompile_headless.sh /path/to/vuln decompile_vuln.c
```

### 範例 2: 反編譯並搜尋特定函數

```bash
./decompile_headless.sh binary.elf all_functions.c
grep -A 50 "main_main" all_functions.c > main_only.c
```

### 範例 3: 批次處理多個檔案

```bash
for binary in challenges/*.elf; do
    output="decompiled/$(basename $binary .elf).c"
    ./decompile_headless.sh "$binary" "$output"
done
```

### 範例 4: 整合到 CTF 工作流程

```bash
# 目錄結構
ctf_challenge/
├── challenge/
│   └── binary
├── ghidra_scripts/
│   └── DecompileCLI.java
├── decompile/
│   └── (生成的 .c 檔案)
└── solution/
    └── solve.py

# 執行反編譯
cd ctf_challenge
/opt/ghidra/support/analyzeHeadless \
    ./ghidra_project TempProject \
    -import ./challenge/binary \
    -scriptPath ./ghidra_scripts \
    -postScript DecompileCLI.java \
    -deleteProject \
    2>/dev/null | grep -v "^INFO\|^WARN\|^ERROR" \
    > decompile/decompile.c

# 分析結果
grep -i "flag\|password\|key" decompile/decompile.c
```

## 常見問題

### Q: 輸出包含很多 Ghidra 日誌怎麼辦？

A: 使用 `grep -v` 過濾日誌：

```bash
analyzeHeadless ... 2>/dev/null | grep -v "^INFO\|^WARN\|^ERROR" > output.c
```

### Q: 如何只反編譯特定函數？

A: 修改 `DecompileCLI.java`，在函數遍歷時加入過濾條件：

```java
FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
while (iter.hasNext() && !monitor.isCancelled()) {
    Function f = iter.next();
    
    // 只處理 main 函數
    if (!f.getName().equals("main")) continue;
    
    DecompileResults res = ifc.decompileFunction(f, 0, monitor);
    // ...
}
```

### Q: Python 腳本為什麼不能用？

A: Ghidra headless 預設不支援 Python (Jython)。需要使用 Java 腳本或啟用 PyGhidra。

**解決方案**:
1. 使用 Java 腳本（推薦）
2. 或安裝 PyGhidra 插件

### Q: 反編譯超時怎麼辦？

A: 使用 `-max-cpu` 參數限制分析時間：

```bash
analyzeHeadless ... -max-cpu 300  # 5 分鐘超時
```

### Q: 如何處理大型二進制檔案？

A: 分段處理或增加記憶體：

```bash
# 增加 JVM 記憶體
export MAXMEM=8G
analyzeHeadless ...
```

## 輸出格式

反編譯輸出格式：

```c
--- Function: function_name ---

void function_name(param_type param1, ...)
{
    // 反編譯的 C 代碼
}

--- Function: next_function ---
...
```

## 進階用法

### 自訂分析選項

在執行前修改 Ghidra 分析器選項：

```bash
analyzeHeadless ... \
    -analysisTimeoutPerFile 600 \
    -processor x86:LE:64:default \
    -cspec gcc
```

### 使用現有專案

不刪除專案以便重複使用：

```bash
# 首次建立專案
analyzeHeadless ./project MyProject -import ./binary

# 後續使用已存在的專案
analyzeHeadless ./project MyProject \
    -process binary \
    -scriptPath ./scripts \
    -postScript DecompileCLI.java
```

### 批次分析多個檔案

```bash
analyzeHeadless ./project BatchProject \
    -import ./binaries \
    -recursive \
    -scriptPath ./scripts \
    -postScript DecompileCLI.java
```

## 參考資料

- [Ghidra Documentation](https://ghidra-sre.org/)
- [Headless Analyzer Guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/HeadlessAnalyzer/HeadlessAnalyzer.htm)
- [Ghidra Script Development](https://ghidra.re/courses/GhidraClass/Intermediate/Scripting_withNotes.html)

## 授權

教育與 CTF 競賽使用。腳本基於 Ghidra 公開 API。
