# GDB 快速參考

## 啟動 GDB

```bash
gdb ./binary
gdb --args ./binary arg1 arg2
gdb -p <PID>

pwndbg
source /usr/share/pwndbg/gdbinit.py

GEF
source /usr/share/gef/gef.py
```

## 基本操作

| 指令 | 簡寫 | 說明 |
|------|------|------|
| `run` | `r` | 執行程式 |
| `continue` | `c` | 繼續執行 |
| `break *0x401234` | `b *0x401234` | 設定中斷點 |
| `info breakpoints` | `i b` | 列出中斷點 |
| `delete 1` | `d 1` | 刪除中斷點 1 |
| `step` | `s` | 單步執行 (進入函數) |
| `next` | `n` | 單步執行 (跳過函數) |
| `nexti` | `ni` | 單步執行 (指令級別) |
| `stepi` | `si` | 單步執行 (指令級別，進入) |
| `finish` | `fin` | 執行到函數返回 |
| `quit` | `q` | 離開 |

## 檢查資訊

```bash
checksec
info functions
info variables
disassemble main
x/20i $rip
x/10gx $rsp
vmmap
search "/bin/sh"
```

## Pwndbg 專屬

```bash
context
stack 20
telescope $rsp 20
rop
rop --grep "pop rdi"
cyclic 200
cyclic -l 0x61616161
got
plt
heap
bins
```

## GEF 專屬

```bash
context
pattern create 200
pattern search 0x61616161
ropper
checksec
elf-info
```

## 檢查記憶體

```bash
x/20wx 0x401000
x/10gx $rsp
x/s 0x404000
x/20i $rip

格式:
x - examine
20 - 數量
w - word (4 bytes)
g - giant (8 bytes)
x - hex
s - string
i - instruction
```

## 斷點技巧

```bash
b main
b *0x401234
b *main+42
b strcmp
```

## 修改值

```bash
set $rax = 0
set $rip = 0x401234
set {long}0x404000 = 0xdeadbeef
```

## 自動化腳本

```bash
gdb -ex 'b main' -ex 'r' -ex 'c' ./binary

或建立 .gdbinit:
set disassembly-flavor intel
b main
run
```

## 查找 Gadgets

```bash
使用 Pwndbg
rop
rop --grep "pop rdi"

使用外部工具
ROPgadget --binary vuln | grep "pop rdi"
ropper --file vuln --search "pop rdi"
```

## Core Dump 分析

```bash
gdb ./binary core
info registers
bt
```

## Pwntools 整合

```python
from pwn import *

io = gdb.debug('./vuln', '''
    b *main
    c
    ni 10
''')
```
