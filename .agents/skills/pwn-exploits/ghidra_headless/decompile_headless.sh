#!/usr/bin/env bash
# Ghidra Headless Decompile Wrapper
# 簡化 Ghidra headless 反編譯流程

set -e

# 顏色輸出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 使用說明
usage() {
	cat <<EOF
Usage: $0 <binary> <output.c> [ghidra_path]

參數:
  binary        要反編譯的二進制檔案
  output.c      輸出的 C 檔案
  ghidra_path   Ghidra 安裝路徑 (可選，預設: \$GHIDRA_PATH 或 /opt/ghidra)

環境變數:
  GHIDRA_PATH   Ghidra 安裝目錄
  MAXMEM        JVM 最大記憶體 (預設: 4G)

範例:
  $0 vuln decompile.c
  $0 ./binary output.c /opt/ghidra
  GHIDRA_PATH=/usr/local/ghidra $0 binary out.c

EOF
	exit 1
}

# 檢查參數
if [ $# -lt 2 ]; then
	usage
fi

BINARY="$1"
OUTPUT="$2"
GHIDRA_PATH="${3:-${GHIDRA_PATH:-/opt/ghidra}}"

# 檢查檔案存在
if [ ! -f "$BINARY" ]; then
	echo -e "${RED}錯誤: 找不到二進制檔案: $BINARY${NC}"
	exit 1
fi

# 檢查 Ghidra 安裝
if [ ! -d "$GHIDRA_PATH" ]; then
	echo -e "${RED}錯誤: 找不到 Ghidra 安裝目錄: $GHIDRA_PATH${NC}"
	echo "請設置 GHIDRA_PATH 環境變數或提供路徑參數"
	exit 1
fi

ANALYZE_HEADLESS="$GHIDRA_PATH/support/analyzeHeadless"
if [ ! -f "$ANALYZE_HEADLESS" ]; then
	echo -e "${RED}錯誤: 找不到 analyzeHeadless: $ANALYZE_HEADLESS${NC}"
	exit 1
fi

# 取得腳本目錄
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 檢查 DecompileCLI.java 是否存在
if [ ! -f "$SCRIPT_DIR/DecompileCLI.java" ]; then
	echo -e "${RED}錯誤: 找不到 DecompileCLI.java${NC}"
	echo "請確保 DecompileCLI.java 與此腳本在同一目錄"
	exit 1
fi

# 建立臨時工作目錄
WORK_DIR=$(mktemp -d -t ghidra-decompile-XXXXXX)
trap "rm -rf $WORK_DIR" EXIT

# 複製腳本到工作目錄
mkdir -p "$WORK_DIR/ghidra_scripts"
cp "$SCRIPT_DIR/DecompileCLI.java" "$WORK_DIR/ghidra_scripts/"

# 取得絕對路徑
BINARY_ABS=$(readlink -f "$BINARY")
OUTPUT_ABS=$(readlink -f "$OUTPUT" 2>/dev/null || echo "$(pwd)/$OUTPUT")
OUTPUT_DIR=$(dirname "$OUTPUT_ABS")

# 建立輸出目錄
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}[*] Ghidra Headless Decompile${NC}"
echo "    Binary: $BINARY_ABS"
echo "    Output: $OUTPUT_ABS"
echo "    Ghidra: $GHIDRA_PATH"
echo ""

# 執行 Ghidra headless
echo -e "${YELLOW}[*] 正在反編譯... (這可能需要幾分鐘)${NC}"

cd "$WORK_DIR"
"$ANALYZE_HEADLESS" \
	./ghidra_project \
	TempProject \
	-import "$BINARY_ABS" \
	-scriptPath ./ghidra_scripts \
	-postScript DecompileCLI.java \
	-deleteProject \
	2>/dev/null | grep -v "^INFO\|^WARN\|^ERROR" >"$OUTPUT_ABS"

# 檢查輸出
if [ ! -s "$OUTPUT_ABS" ]; then
	echo -e "${RED}[!] 錯誤: 反編譯失敗或輸出為空${NC}"
	exit 1
fi

# 統計資訊
LINE_COUNT=$(wc -l <"$OUTPUT_ABS")
SIZE=$(du -h "$OUTPUT_ABS" | cut -f1)

echo -e "${GREEN}[✓] 完成!${NC}"
echo "    行數: $LINE_COUNT"
echo "    大小: $SIZE"
echo "    輸出: $OUTPUT_ABS"
