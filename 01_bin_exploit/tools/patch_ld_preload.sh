#!/bin/bash
# Patch binary with LD_PRELOAD to inject custom libc or shared library
# Usage: patch_ld_preload.sh <binary> <library_path>
# Example: patch_ld_preload.sh ./vuln ./exploit.so

if [ $# -ne 2 ]; then
	echo "Usage: $0 <binary> <library_path>"
	echo "Example: $0 ./vuln ./exploit.so"
	echo ""
	echo "This script sets up LD_PRELOAD environment for testing exploitation."
	exit 1
fi

BINARY=$1
LIBRARY=$2

if [ ! -f "$BINARY" ]; then
	echo "[-] Binary not found: $BINARY"
	exit 1
fi

if [ ! -f "$LIBRARY" ]; then
	echo "[-] Library not found: $LIBRARY"
	exit 1
fi

# Get absolute paths
BINARY_ABS=$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")
LIBRARY_ABS=$(cd "$(dirname "$LIBRARY")" && pwd)/$(basename "$LIBRARY")

echo "[*] Setting up LD_PRELOAD for exploitation testing"
echo "[*] Binary: $BINARY_ABS"
echo "[*] Library: $LIBRARY_ABS"
echo ""

# Create wrapper script
WRAPPER="${BINARY}.preload"

cat >"$WRAPPER" <<'EOF'
#!/bin/bash
export LD_PRELOAD="$LIBRARY_ABS"
exec "$BINARY_ABS" "$@"
EOF

# Replace placeholders
sed -i "s|LIBRARY_ABS|$LIBRARY_ABS|g" "$WRAPPER"
sed -i "s|BINARY_ABS|$BINARY_ABS|g" "$WRAPPER"

chmod +x "$WRAPPER"

echo "[+] Created wrapper script: $WRAPPER"
echo "[+] Run with: $WRAPPER"
echo ""
echo "[*] Or set LD_PRELOAD manually:"
echo "    export LD_PRELOAD=$LIBRARY_ABS"
echo "    $BINARY_ABS"
echo ""
echo "[*] Or in single command:"
echo "    LD_PRELOAD=$LIBRARY_ABS $BINARY_ABS"
