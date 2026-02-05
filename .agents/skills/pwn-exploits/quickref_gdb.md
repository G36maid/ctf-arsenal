# GDB / pwndbg / GEF 快速參考

GDB 調試速查表，重點支援 pwndbg 和 GEF。

## 設定 GDB

### 載入 pwndbg

```bash
# 複製設定檔
cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit

# 或手動加入 ~/.gdbinit
echo 'source /usr/share/pwndbg/gdbinit.py' >> ~/.gdbinit
echo 'set disassembly-flavor intel' >> ~/.gdbinit
```

### 載入 GEF

```bash
# 複製設定檔
cp 01_bin_exploit/gdb_init/gdbinit-gef ~/.gdbinit

# 或手動加入
echo 'source /usr/share/gef/gef.py' >> ~/.gdbinit
echo 'set disassembly-flavor intel' >> ~/.gdbinit
```

## 啟動 GDB

### 從命令列

```bash
# 直接啟動
gdb ./vuln

# 帶參數
gdb --args ./vuln arg1 arg2

# Attach 到 process
gdb -p <pid>
```

### 從 pwntools

```python
# 在 solve.py 中
io = gdb.debug([exe], gdbscript=gdbscript)

# 自定義 GDB 腳本
gdbscript = """
b *main+123
continue
telescope $rsp 20
"""
```

### 執行模式

```bash
# 使用模板腳本
python solve.py GDB
```

## 基本 GDB 命令

### 執行控制

```gdb
# 執行程式
run                    # 或 r
run arg1 arg2          # 帶參數

# 繼續執行
continue               # 或 c

# 單步執行
stepi                  # 或 si (進入函數)
nexti                  # 或 ni (跳過函數)
step                   # 或 s  (source 級別)
next                   # 或 n  (source 級別)

# 執行到特定位置
finish                 # 執行到當前函數返回
until *0x401234        # 執行到指定地址
```

### 斷點

```gdb
# 設定斷點
break main             # 或 b main (函數名)
break *0x401234        # 或 b *0x401234 (地址)
break *main+123        # 偏移量

# 條件斷點
break *0x401234 if $rax == 0

# 查看斷點
info breakpoints       # 或 i b

# 刪除斷點
delete 1               # 刪除編號 1 的斷點
delete                 # 刪除所有斷點

# 停用/啟用斷點
disable 1
enable 1
```

### 查看資訊

```gdb
# 查看暫存器
info registers         # 或 i r
info registers rax     # 查看特定暫存器

# 查看 stack
x/20x $rsp             # 16 進位顯示
x/20gx $rsp            # 64-bit 16 進位 (x64)
x/20wx $esp            # 32-bit 16 進位 (x86)

# 查看記憶體
x/s 0x401234           # 顯示字串
x/i $rip               # 顯示指令
x/10i $rip             # 顯示 10 條指令

# 反組譯
disassemble main       # 或 disas main
disassemble 0x401234

# 查看 backtrace
backtrace              # 或 bt
```

### 記憶體檢視格式

```gdb
# x/[數量][格式][大小] [地址]
# 格式: x(hex), d(decimal), s(string), i(instruction)
# 大小: b(byte), h(halfword), w(word), g(giant, 8bytes)

x/20gx $rsp            # 20 個 8-byte hex
x/10i $rip             # 10 條指令
x/s 0x401234           # 字串
```

## pwndbg 特有命令

### 上下文顯示

```gdb
# 顯示完整上下文 (暫存器、反組譯、stack)
context                # 或 ctx

# 只顯示特定部分
context regs
context disasm
context stack
context backtrace

# 自定義上下文
set context-sections "regs disasm stack"
```

### Stack 檢視

```gdb
# telescope: 智慧顯示 stack 內容
telescope $rsp         # 從 RSP 開始
telescope $rsp 30      # 顯示 30 個值

# 簡寫
tel $rsp
```

### 記憶體映射

```gdb
# 查看記憶體映射
vmmap

# 查看特定映射
vmmap libc
vmmap heap
vmmap stack
```

### PIE 處理

```gdb
# 計算 PIE base
piebase

# 使用 PIE 相對地址
b *$rebase(0x1234)     # 斷點在 base+0x1234
```

### GOT/PLT

```gdb
# 查看 GOT 表
got

# 查看特定 GOT entry
got puts

# 查看 PLT
plt
```

### 搜尋

```gdb
# 搜尋 pattern
search "flag{"
search -t string "/bin/sh"
search -t int 0x41414141

# 搜尋 gadgets
ropsearch "pop rdi"
```

### Heap 分析

```gdb
# 查看 heap
heap
heap chunks
heap bins

# 追蹤 heap
heap-analysis-helper
```

### Cyclic Pattern

```gdb
# 生成 cyclic pattern
cyclic 500

# 找 offset
cyclic -l 0x61616163
cyclic -l caaa
```

## GEF 特有命令

### 上下文顯示

```gdb
# GEF 自動顯示 context

# 設定要顯示的區塊
gef config context.layout "regs code stack"
```

### 記憶體檢視

```gdb
# 類似 pwndbg 的 telescope
dereference $rsp
dereference $rsp 20

# 簡寫
deref $rsp
```

### 記憶體映射

```gdb
# 查看記憶體映射
vmmap

# 搜尋
vmmap libc
```

### 搜尋

```gdb
# 搜尋 pattern
grep "flag{"
search-pattern "flag{"
search-pattern "/bin/sh" libc
```

### ROPgadget 整合

```gdb
# 找 ROP gadgets
ropper
ropper --search "pop rdi"

# 或使用 GEF 內建
rop-gadget
```

### 格式化字串

```gdb
# 格式化字串漏洞分析
format-string-helper
```

## 實用技巧

### Pwntools 整合

```python
# 在 solve.py 中
gdbscript = """
# 設定斷點
b *vuln+123

# 繼續執行
continue

# 自動化檢查
telescope $rsp 20
got
vmmap
""".format(**locals())

io = gdb.debug([exe], gdbscript=gdbscript)
```

### 自動化 offset 查找

```python
# 啟動 GDB
io = gdb.debug([exe])
io.sendline(cyclic(500))
io.wait()

# 讀取 core file
core = io.corefile
offset = cyclic_find(core.rsp)  # x64
print(f"Offset: {offset}")
```

### 查找 libc base

```gdb
# 在 GDB 中
got              # 查看已解析的函數
x/gx &puts       # 讀取 puts@got
# 然後手動計算: leak - puts_offset
```

### 檢查 stack alignment

```gdb
# x64 在呼叫函數前，RSP 需要 16-byte 對齊
p/x $rsp & 0xf
# 應該是 0x8 (因為 call 會 push return address)
```

### 快速洩漏 canary

```gdb
# 在函數開頭斷點
b *main

# 查看 canary (FS:0x28)
x/gx $fs_base+0x28

# 或使用 pwndbg
canary
```

## 常用組合命令

### ret2libc 調試

```gdb
# 斷在 vulnerable function
b *vuln+offset

# 繼續執行
continue

# 檢查 ROP chain
telescope $rsp 30

# 查看即將執行的指令
x/10i $rip

# 單步到 ret
ni

# 檢查 return address
x/gx $rsp
```

### 檢查 payload

```gdb
# 在發送 payload 後斷點
b *vuln+offset
continue

# 查看 stack 內容
telescope $rsp 40

# 查看 canary 是否被覆蓋
canary

# 查看 saved RIP
x/gx $rbp+8
```

## 設定檔優化

### ~/.gdbinit 建議設定

```python
# 載入 pwndbg
source /usr/share/pwndbg/gdbinit.py

# Intel 語法
set disassembly-flavor intel

# 顯示設定
set context-sections "regs disasm stack backtrace"

# 關閉分頁
set pagination off

# 顯示所有 thread
set print thread-events on

# History
set history save on
set history size 10000
set history filename ~/.gdb_history
```

## 快速參考卡

### 執行
```
r / run          - 執行
c / continue     - 繼續
si / stepi       - 單步 (進入)
ni / nexti       - 單步 (跳過)
finish           - 執行到返回
```

### 斷點
```
b main           - 函數斷點
b *0x401234      - 地址斷點
i b              - 查看斷點
delete 1         - 刪除斷點
```

### 查看
```
i r              - 暫存器
x/20gx $rsp      - Stack (hex)
disas main       - 反組譯
bt               - Backtrace
```

### pwndbg
```
context          - 顯示上下文
telescope $rsp   - 智慧 stack 顯示
vmmap            - 記憶體映射
got              - GOT 表
piebase          - PIE base
```

### GEF
```
vmmap            - 記憶體映射
dereference $rsp - Stack 顯示
ropper           - ROP gadgets
grep             - 搜尋
```

## 參考資料

- [pwndbg GitHub](https://github.com/pwndbg/pwndbg)
- [GEF GitHub](https://github.com/hugsy/gef)
- [GDB 官方文檔](https://sourceware.org/gdb/documentation/)
