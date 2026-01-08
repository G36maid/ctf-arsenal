#!/bin/bash
# 設置 Ruby gems PATH
# 使用方式: source scripts/setup_gem_path.sh

GEM_BIN_DIR="$HOME/.local/share/gem/ruby/3.4.0/bin"

# 檢查是否已經在 PATH 中
if [[ ":$PATH:" != *":$GEM_BIN_DIR:"* ]]; then
	export PATH="$GEM_BIN_DIR:$PATH"
	echo "✓ 已將 Ruby gems bin 目錄添加到 PATH"
	echo "  $GEM_BIN_DIR"
else
	echo "✓ Ruby gems bin 目錄已在 PATH 中"
fi

# 驗證工具
echo ""
echo "=== 驗證工具 ==="
if command -v one_gadget &>/dev/null; then
	echo "✓ one_gadget: $(one_gadget --version 2>&1 | head -1)"
else
	echo "✗ one_gadget: 未找到"
fi

if command -v seccomp-tools &>/dev/null; then
	echo "✓ seccomp-tools: $(seccomp-tools --version 2>&1 | head -1)"
else
	echo "✗ seccomp-tools: 未找到"
fi

echo ""
echo "提示: 如需永久添加此 PATH，請將以下行添加到 ~/.zshrc:"
echo "  export PATH=\"\$HOME/.local/share/gem/ruby/3.4.0/bin:\$PATH\""
