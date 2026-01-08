# 📚 CTF Arsenal - 文檔中心

本目錄包含專案的詳細文檔與參考資料。

## 📖 文檔列表

### 核心文檔

#### [`SESSION_SUMMARY.md`](SESSION_SUMMARY.md) ⭐ 最重要
**完整專案總覽**
- 專案目標與結構
- 安裝決策與技術選型
- 使用指南與競賽策略
- 疑難排解與參考資源

**推薦閱讀順序**: 第一個閱讀

#### [`INSTALL_INSTRUCTIONS.md`](INSTALL_INSTRUCTIONS.md)
**詳細安裝說明**
- 使用 uv 管理 Python 套件
- 系統套件安裝指令
- Ruby gems 安裝
- GDB 設定
- 安裝後測試

**適合**: 首次安裝或重新安裝時參考

#### [`SYSTEM_CHECK.md`](SYSTEM_CHECK.md)
**工具安裝檢查清單**
- 已安裝工具列表
- 缺失工具列表
- 版本資訊

**適合**: 快速檢查環境是否完整

---

### 參考資料

#### [`ARCH_PACKAGES.md`](ARCH_PACKAGES.md)
**Arch Linux 套件參考**
- 所有 pacman/paru 套件清單
- 套件說明與用途
- 安裝指令

#### [`GIT_COMMITS.md`](GIT_COMMITS.md)
**Git 提交規範與歷史**
- Conventional Commits 格式
- 提交歷史總覽
- Git 工作流程建議

---

## 🚀 快速導航

### 我該讀哪份文檔？

| 情境 | 推薦文檔 |
|------|---------|
| **第一次使用專案** | → [`SESSION_SUMMARY.md`](SESSION_SUMMARY.md) |
| **安裝工具** | → [`INSTALL_INSTRUCTIONS.md`](INSTALL_INSTRUCTIONS.md) |
| **檢查環境** | → [`SYSTEM_CHECK.md`](SYSTEM_CHECK.md) |
| **競賽前準備** | → [`SESSION_SUMMARY.md`](SESSION_SUMMARY.md#-critical-pre-competition-checklist) |
| **遇到問題** | → [`SESSION_SUMMARY.md`](SESSION_SUMMARY.md#-common-issues--solutions) |
| **需要 Arch 套件清單** | → [`ARCH_PACKAGES.md`](ARCH_PACKAGES.md) |
| **了解 Git 歷史** | → [`GIT_COMMITS.md`](GIT_COMMITS.md) |

---

## 📂 其他重要文檔位置

### 快速參考 (Cheat Sheets)
位於 [`../cheat_sheets/`](../cheat_sheets/)
- [`ettercap_usage.md`](../cheat_sheets/ettercap_usage.md) - ⚠️ 工控題必讀
- [`gdb_cheatsheet.md`](../cheat_sheets/gdb_cheatsheet.md) - GDB/pwndbg 指令
- [`linux_commands.md`](../cheat_sheets/linux_commands.md) - Linux 常用指令

### 安裝腳本
位於 [`../scripts/`](../scripts/)
- `setup-arch-paru.sh` - Arch Linux 自動安裝
- `setup.sh` - 通用版本
- `INSTALL_INSTRUCTIONS.sh` - Python 環境設定

### 主要文檔
- [`../README.md`](../README.md) - 專案首頁與快速開始

---

## 💡 文檔維護

### 文檔組織原則
1. **根目錄**: 只保留 README.md (入口文檔)
2. **docs/**: 詳細參考文檔與技術說明
3. **cheat_sheets/**: 競賽中快速查閱的指令參考

### 新增文檔時
- 技術說明 → 放在 `docs/`
- 快速參考 → 放在 `cheat_sheets/`
- 更新本 README.md 的文檔列表

---

**建議**: 競賽前一天重新閱讀 [`SESSION_SUMMARY.md`](SESSION_SUMMARY.md)
