#!/bin/bash
# CTF Arsenal 安裝指令 (使用 uv)

echo "=== CTF Arsenal 安裝 (uv 版本) ==="
echo ""

echo "[1/5] 安裝系統套件 (需要你確認)..."
echo "執行: paru -S --needed gdb pwndbg ettercap socat tcpdump gef peda"
paru -S --needed gdb pwndbg ettercap socat tcpdump gef peda

echo ""
echo "[2/5] 安裝 Ruby gems..."
sudo gem install one_gadget seccomp-tools

echo ""
echo "[3/5] 使用 uv 安裝 Python 套件..."
if [ ! -d ".venv" ]; then
    echo "建立虛擬環境..."
    uv venv
fi

echo "安裝套件..."
uv pip install pwntools requests beautifulsoup4 pycryptodome

echo "安裝系統級 scapy (需要 root 權限)..."
paru -S --needed python-scapy

echo ""
echo "[4/5] 設定 GDB (pwndbg)..."
if [ ! -f ~/.gdbinit ]; then
    echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit
    echo "  ✓ 已建立 ~/.gdbinit"
else
    echo "  ⊘ ~/.gdbinit 已存在，跳過"
    echo "  手動設定: echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit"
fi

echo ""
echo "[5/5] 啟用 IP Forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo ""
echo "=== 安裝完成！驗證工具... ==="
echo ""

echo "✓ GDB: $(gdb --version 2>&1 | head -1)"
echo "✓ Ettercap: $(ettercap --version 2>&1 | head -1)"
echo "✓ Socat: $(socat -V 2>&1 | head -1)"
echo "✓ Ruby gems:"
gem list | grep -E "one_gadget|seccomp" | sed 's/^/  /'

echo ""
echo "✓ Python (uv):"
source .venv/bin/activate
python -c "from pwn import *; print('  Pwntools:', pwnlib.__version__)"
python -c "import requests; print('  Requests:', requests.__version__)"
python -c "import bs4; print('  BeautifulSoup4: OK')"

echo ""
echo "✓ Scapy (系統):"
python -c "from scapy.all import *; print('  Scapy: OK')" 2>/dev/null || echo "  Scapy: 需要用 sudo"

echo ""
echo "✓ IP Forwarding: $(sysctl -n net.ipv4.ip_forward)"

echo ""
echo "🎯 使用方式:"
echo "  1. 啟動環境: source .venv/bin/activate"
echo "  2. 或使用: uv run python script.py"
echo "  3. Scapy 腳本: sudo python script.py"
echo "  4. Ettercap: sudo ettercap -T -i eth0 -M arp"
echo ""
echo "📖 查看文件: cat INSTALL_INSTRUCTIONS.md"
