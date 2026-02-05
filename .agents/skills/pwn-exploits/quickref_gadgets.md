# ROP Gadgets 快速查找

快速查找 ROP gadgets 的命令參考。

## ROPgadget

### 基本使用

```bash
# 列出所有 gadgets
ROPgadget --binary vuln

# 搜尋特定 gadget
ROPgadget --binary vuln | grep "pop rdi"

# 只顯示 unique gadgets
ROPgadget --binary vuln --unique
```

### 常用搜尋

```bash
# x64 常用 gadgets
ROPgadget --binary vuln | grep "pop rdi"
ROPgadget --binary vuln | grep "pop rsi"
ROPgadget --binary vuln | grep "pop rdx"
ROPgadget --binary vuln | grep "pop rax"
ROPgadget --binary vuln | grep "ret$"

# x86 常用 gadgets
ROPgadget --binary vuln | grep "pop ebx"
ROPgadget --binary vuln | grep "pop esi"
ROPgadget --binary vuln | grep "pop edi"
```

### 搜尋 syscall

```bash
# 找 syscall gadget
ROPgadget --binary vuln | grep "syscall"
ROPgadget --binary vuln | grep "int 0x80"
```

### 搜尋字串

```bash
# 在二進制檔中找字串
ROPgadget --binary vuln --string "/bin/sh"
ROPgadget --binary vuln --string "sh"

# 在 libc 中找字串
ROPgadget --binary libc.so.6 --string "/bin/sh"
```

### 進階搜尋

```bash
# 只看特定類型
ROPgadget --binary vuln --only "pop|ret"
ROPgadget --binary vuln --only "mov|ret"

# 排除特定 gadgets
ROPgadget --binary vuln --norop
ROPgadget --binary vuln --nosys

# 限制深度 (加快搜尋)
ROPgadget --binary vuln --depth 5
```

### 自動 ROP chain 生成

```bash
# 生成 execve("/bin/sh") 的 chain
ROPgadget --binary vuln --ropchain

# 輸出到文件
ROPgadget --binary vuln --ropchain > chain.py
```

## ropper

### 基本使用

```bash
# 啟動 ropper
ropper --file vuln

# 列出所有 gadgets
ropper --file vuln --all

# 搜尋特定 gadget
ropper --file vuln --search "pop rdi"
```

### 進入互動模式

```bash
ropper --file vuln

# 在互動模式中
(vuln)> search pop rdi
(vuln)> search pop rsi; pop r15
(vuln)> search mov ?ax, ?bx
```

### 搜尋語法

```bash
# 精確搜尋
ropper --file vuln --search "pop rdi; ret"

# 萬用字元
ropper --file vuln --search "pop %; ret"
ropper --file vuln --search "mov ?ax, ?bx"

# 正規表達式
ropper --file vuln --regex "pop (rdi|rsi)"
```

### 搜尋 syscall 和字串

```bash
# syscall gadgets
ropper --file vuln --search "syscall"
ropper --file vuln --search "int 0x80"

# 字串搜尋
ropper --file vuln --string "/bin/sh"
```

### 多檔案搜尋

```bash
# 同時搜尋 binary 和 libc
ropper --file vuln --file libc.so.6 --search "pop rdi"
```

### 其他選項

```bash
# 只顯示地址
ropper --file vuln --search "pop rdi" --nocolor | awk '{print $1}'

# 設定架構
ropper --file vuln --arch x86
ropper --file vuln --arch x86_64

# Chain 生成
ropper --file vuln --chain "execve"
```

## rp++ (Roper)

### 基本使用

```bash
# 找所有 gadgets
rp++ -f vuln -r 1

# 只顯示 unique
rp++ -f vuln -r 1 --unique

# 限制深度
rp++ -f vuln -r 5
```

### 搜尋

```bash
# 搜尋特定指令
rp++ -f vuln -r 1 | grep "pop rdi"

# 進階搜尋
rp++ -f vuln -r 3 --unique | grep -E "(pop|mov)"
```

## 典型 x64 Gadgets

### 函數參數設定 (System V ABI)

```
pop rdi; ret          # 第 1 個參數 (RDI)
pop rsi; pop r15; ret # 第 2 個參數 (RSI) - 注意 r15 也被 pop
pop rdx; ret          # 第 3 個參數 (RDX)
pop rcx; ret          # 第 4 個參數 (RCX)
pop r8; ret           # 第 5 個參數 (R8)
pop r9; ret           # 第 6 個參數 (R9)
```

### Stack alignment

```
ret                   # 單純 ret，用於對齊 RSP
```

### Syscall

```
pop rax; ret          # 設定 syscall number
syscall               # 執行 syscall
```

### 記憶體操作

```
mov [reg], reg; ret   # 寫入記憶體
mov reg, [reg]; ret   # 讀取記憶體
```

### 常用組合

```bash
# ret2libc 需要的 gadgets
pop rdi; ret          # puts(got_entry)
ret                   # stack alignment
pop rdi; ret          # system("/bin/sh")
```

## 典型 x86 Gadgets

### 函數參數設定 (cdecl)

```
pop eax; ret          # 暫存器操作
pop ebx; ret
pop ecx; ret
pop edx; ret
pop esi; ret
pop edi; ret
```

**注意**: x86 參數通常在 stack 上，不需要設定暫存器

### Syscall

```
pop eax; ret          # syscall number
int 0x80              # 執行 syscall
```

### 記憶體操作

```
mov [reg], reg; ret
mov reg, [reg]; ret
```

## one_gadget (特殊)

### 使用方式

```bash
# 列出所有 one_gadget
one_gadget libc.so.6

# 指定 libc 版本
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# 指定 build-id
one_gadget --build-id 12345678
```

### 輸出範例

```
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

### 使用 one_gadget

```python
# 在 Python exploit 中
one_gadget_offset = 0x4f322
one_gadget_addr = libc_base + one_gadget_offset

payload = flat({
    offset: one_gadget_addr
})
```

**注意**: 使用前需確認 constraints 滿足！

## 快速腳本

### find_gadgets_ropgadget.sh

```bash
#!/bin/bash
# 使用 ROPgadget 快速找常用 gadgets
BINARY=${1:-vuln}

echo "[+] pop rdi; ret"
ROPgadget --binary "$BINARY" | grep "pop rdi ; ret$"

echo "[+] pop rsi; pop r15; ret"
ROPgadget --binary "$BINARY" | grep "pop rsi.*pop r15.*ret$"

echo "[+] pop rdx; ret"
ROPgadget --binary "$BINARY" | grep "pop rdx.*ret$"

echo "[+] ret"
ROPgadget --binary "$BINARY" | grep "^[^:]*: ret$" | head -5
```

### find_gadgets_ropper.sh

```bash
#!/bin/bash
# 使用 ropper 快速找常用 gadgets
BINARY=${1:-vuln}

echo "[+] pop rdi; ret"
ropper --file "$BINARY" --search "pop rdi; ret" --nocolor

echo "[+] pop rsi; pop r15; ret"
ropper --file "$BINARY" --search "pop rsi; pop r15; ret" --nocolor

echo "[+] pop rdx; ret"
ropper --file "$BINARY" --search "pop rdx; ret" --nocolor

echo "[+] ret"
ropper --file "$BINARY" --search "ret" --nocolor | head -10
```

## 常見問題

### 找不到 pop rdi gadget

**解決**:
1. 搜尋 libc: `ROPgadget --binary libc.so.6 | grep "pop rdi"`
2. 使用替代方案: `pop rax; ret` + `mov rdi, rax; ret`

### pop rsi 總是連帶 pop r15

**這很常見**，使用時注意:
```python
payload = flat({
    offset: [
        pop_rsi_r15,
        arg2,      # RSI
        0xdeadbeef # R15 (dummy)
    ]
})
```

### gadget 地址有 null byte

**解決**:
1. 尋找其他地址的相同 gadget
2. 使用 libc 中的 gadget (libc base + offset)
3. 考慮使用 partial overwrite

## 參考資料

- [ROPgadget GitHub](https://github.com/JonathanSalwan/ROPgadget)
- [ropper GitHub](https://github.com/sashs/Ropper)
- [one_gadget GitHub](https://github.com/david942j/one_gadget)
- [rp++ GitHub](https://github.com/0vercl0k/rp)
