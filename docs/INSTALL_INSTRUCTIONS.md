# CTF Arsenal - 安裝指令 (使用 uv 管理 Python)

## 🔧 立即執行這些指令

### 1. 安裝系統套件 (需要你手動執行)
```bash
# 安裝缺失的 5 個工具
paru -S --needed gdb pwndbg ettercap socat tcpdump

# 可選: GEF 和 PEDA (如果想要多個 GDB 增強工具)
paru -S --needed gef peda ropper
```

### 2. 安裝 Ruby gems
```bash
sudo gem install one_gadget seccomp-tools
```

### 3. Python 套件 (使用 uv)
```bash
# 檢查 python-scapy 是否為系統套件
paru -S --needed python-scapy

# 或使用 uv 安裝到專案環境
cd ctf-arsenal
uv venv
source .venv/bin/activate
uv pip install pwntools scapy requests beautifulsoup4 pycryptodome
```

### 4. 設定 GDB (選擇一個)
```bash
# 推薦: pwndbg (最適合 CTF)
echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit

# 或: gef (多架構支援)
# echo 'source /usr/share/gef/gef.py' > ~/.gdbinit

# 或: peda (經典)
# echo 'source /usr/share/peda/peda.py' > ~/.gdbinit
```

### 5. 啟用 IP Forwarding (工控題必須)
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## 📝 使用 uv 的建議結構

由於你使用 uv 管理 Python，建議這樣配置：

### 建立專案虛擬環境
```bash
cd ctf-arsenal

# 建立 .python-version (可選)
echo "3.12" > .python-version

# 初始化 uv 專案
uv init --no-workspace

# 安裝 CTF 相關套件
uv add pwntools scapy requests beautifulsoup4 pycryptodome
```

### 使用方式
```bash
# 啟動環境
cd ctf-arsenal
source .venv/bin/activate

# 或直接用 uv run
uv run python .agents/skills/pwn-exploits/templates/pwn_basic.py
```

---

## 🎯 一鍵複製執行

```bash
# === 第一步: 安裝系統套件 ===
paru -S --needed gdb pwndbg ettercap socat tcpdump gef peda

# === 第二步: Ruby gems ===
sudo gem install one_gadget seccomp-tools

# === 第三步: Python (uv) ===
cd ctf-arsenal
uv venv
source .venv/bin/activate
uv pip install pwntools scapy requests beautifulsoup4 pycryptodome

# === 第四步: 設定 GDB ===
echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit

# === 第五步: IP Forwarding ===
sudo sysctl -w net.ipv4.ip_forward=1

# === 驗證安裝 ===
gdb --version | head -1
ettercap --version 2>&1 | head -1
gem list | grep -E "one_gadget|seccomp"
uv run python -c "from pwn import *; print('✓ Pwntools OK')"
uv run python -c "from scapy.all import *; print('✓ Scapy OK')"
```

---

## 🔍 檢查你的 uv 環境

你已安裝 uv 0.9.21，建議：

1. **系統級套件**: scapy (需要 root 權限的最好用系統套件)
   ```bash
   paru -S python-scapy
   ```

2. **專案級套件**: pwntools, requests 等 (用 uv 管理)
   ```bash
   uv pip install pwntools requests beautifulsoup4
   ```

這樣可以：
- `sudo python script.py` 使用系統的 scapy
- `uv run python script.py` 使用專案的 pwntools

---

## ⚠️ 重要提醒

### Scapy 權限問題
Scapy 需要 raw socket 權限，有兩個選擇：

**選項 1: 使用系統套件 + sudo** (推薦)
```bash
paru -S python-scapy
sudo python script.py
```

**選項 2: 使用 uv + sudo**
```bash
sudo $(which uv) run python script.py
# 或
sudo .venv/bin/python script.py
```

### Pwntools 與 uv
Pwntools 在虛擬環境中運行良好：
```bash
uv pip install pwntools
uv run python exploit.py
```

---

## 📋 安裝後測試

```bash
# 測試系統工具
gdb --version
ettercap --version
socat -V
tcpdump --version

# 測試 Ruby gems
gem list | grep one_gadget
gem list | grep seccomp

# 測試 Python (uv)
cd ctf-arsenal
uv run python -c "from pwn import *; print('Pwntools:', pwnlib.__version__)"
uv run python -c "import requests; print('Requests:', requests.__version__)"

# 測試 Scapy (系統套件)
sudo python -c "from scapy.all import *; print('Scapy OK')"

# 測試 GDB
gdb -q -ex 'quit'
```

---

## 🚀 建議的工作流程

### 開發 Exploit
```bash
cd ctf-arsenal
uv run python .agents/skills/pwn-exploits/templates/pwn_basic.py
```

### 使用 Scapy (需要 root)
```bash
cd ctf-arsenal/.agents/skills/ics-traffic/scapy_scripts
sudo python modbus_sniffer.py
```

### 使用 Ettercap
```bash
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.100/
```
