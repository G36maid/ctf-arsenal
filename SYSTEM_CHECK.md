# CTF Arsenal - 系統檢查報告

## ✅ 已安裝工具

### 核心工具
- **Python 3**: ✅ `/usr/bin/python3`
- **Ruby**: ✅ `/usr/bin/ruby`
- **Rust**: ✅ `/usr/bin/rustc`
- **Nmap**: ✅ `/usr/bin/nmap`

### Python 套件
- **python-pwntools**: ✅ (pacman 已安裝，但需測試)
- **requests**: ✅ 2.32.5
- **scapy**: ❌ 需安裝
- **beautifulsoup4**: 未測試

### 工具套件
- **ropgadget**: ✅ (pacman 已安裝)
- **bettercap**: ✅ (MITM 替代工具)
- **wireshark-cli** (tshark): ✅

---

## ❌ 需要安裝的關鍵工具

### Binary Exploitation (高優先)
- **gdb**: ❌ 未安裝
- **pwndbg**: ❌ 未安裝
- **gef**: ❌ 未安裝
- **ropper**: ❌ 未安裝

### ICS/工控情境 (必須！)
- **ettercap**: ❌ 未安裝 (官方指定工具)
- **scapy**: ❌ 未安裝 (Python 模組)
- **tcpdump**: ❌ 未安裝
- **socat**: ❌ 未安裝

### Ruby Gems
- **one_gadget**: ❌ 未安裝
- **seccomp-tools**: ❌ 未安裝

---

## 🔧 修正後的安裝指令

### 必須立即安裝 (比賽關鍵工具)
```bash
# Binary Exploitation 核心
sudo pacman -S gdb pwndbg gef ropper

# 工控情境 (Ettercap 必須！)
sudo pacman -S ettercap socat tcpdump

# Python 套件
sudo pacman -S python-scapy python-beautifulsoup4

# Ruby gems
sudo gem install one_gadget seccomp-tools
```

### 可選安裝 (增強功能)
```bash
# GUI Wireshark
sudo pacman -S wireshark-qt

# 靜態分析工具
sudo pacman -S radare2 ghidra

# Web 工具
sudo pacman -S sqlmap
```

---

## 📝 setup.sh 需要修改的部分

原本的 `setup.sh` 假設所有工具都未安裝，但系統已有：
- ✅ python-pwntools
- ✅ ropgadget
- ✅ bettercap (可替代 Ettercap 部分功能)
- ✅ nmap, ruby, rustc

建議執行：
```bash
cd ctf-arsenal
bash setup.sh 2>&1 | tee setup.log
```

如果遇到 pacman 錯誤 "target already installed"，可忽略。

---

## ⚠️ 立即行動項

比賽前 **必須** 安裝：

1. **GDB + pwndbg** (Binary 題必須)
   ```bash
   sudo pacman -S gdb pwndbg
   echo 'source /usr/share/pwndbg/gdbinit.py' >> ~/.gdbinit
   ```

2. **Ettercap** (工控情境題官方指定)
   ```bash
   sudo pacman -S ettercap
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

3. **Scapy** (封包操作)
   ```bash
   sudo pacman -S python-scapy
   ```

4. **測試 pwntools**
   ```bash
   python3 -c "from pwn import *; print(context.arch)"
   ```

---

## 🎯 簡化安裝指令

```bash
# 一行安裝所有缺失工具
sudo pacman -S gdb pwndbg gef ropper ettercap socat tcpdump python-scapy python-beautifulsoup4 && sudo gem install one_gadget seccomp-tools

# 設定 GDB
echo 'source /usr/share/pwndbg/gdbinit.py' >> ~/.gdbinit

# 啟用 IP forwarding (工控題必須)
sudo sysctl -w net.ipv4.ip_forward=1

# 測試
python3 -c "from pwn import *; print('Pwntools OK')"
sudo ettercap -T -h | head -5
```
