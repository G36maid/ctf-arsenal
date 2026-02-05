# Ground Truth Bomb - 快速開始指南

## 🎯 立即開始拆除炸彈

### 方法 1：交互式計算（推薦）
```bash
cd csc2025/GrounTruth
python3 defuse_tool.py
```

然後：
1. 輸入裝置顯示的 Seed（10 個 hex 字符）
2. 查看生成的完整剪線順序（16 步）
3. 按照 STEP 1 到 STEP 16 的順序剪線

### 方法 2：直接查看生成的文件
```bash
cat cutting_sequence_[your_seed].txt
```

---

## 📍 電路板快速參考

```
    ┌──────────────────────┐
    │ GPIO 8  │  GPIO 0     │  ← 頂部標記
    │ (Pin 0)  │  (Pin 8)     │
    ├──────────────────────┤
    │ GPIO 9-15             │  ← 右側 (Pin 1-7)
    ├──────────────────────┤
    │ GPIO 22-16            │  ← 底部 (Pin 9-15)
    └──────────────────────┘
```

---

## ⚡ 快速剪線步驟（以 deadbeef01 為例）

| 步驟 | GPIO | 位置 | 操作 |
|-------|------|------|------|
| 1 | 10 | 右側 | 剪斷 GPIO 10 |
| 2 | 14 | 右側 | 剪斷 GPIO 14 |
| 3 | 15 | 右側 | 剪斷 GPIO 15 |
| 4 | 11 | 右側 | 剪斷 GPIO 11 |
| 5 | 22 | 底部 | 剪斷 GPIO 22 |
| 6 | 12 | 右側 | 剪斷 GPIO 12 |
| 7 | 19 | 底部 | 剪斷 GPIO 19 |
| 8 | 8 | ⬅ 左上角 | 剪斷 GPIO 8 |
| 9 | 20 | 底部 | 剪斷 GPIO 20 |
| 10 | 18 | 底部 | 剪斷 GPIO 18 |
| 11 | 17 | 底部 | 剪斷 GPIO 17 |
| 12 | 13 | 右側 | 剪斷 GPIO 13 |
| 13 | 0 | ➡ 右上角 | 剪斷 GPIO 0 |
| 14 | 9 | 右側 | 剪斷 GPIO 9 |
| 15 | 21 | 底部 | 剪斷 GPIO 21 |
| 16 | 16 | 底部 | 剪斷 GPIO 16 → 🏆 WIN! |

---

## ✅ 成功條件

- ✅ 按順序剪線（1 → 2 → ... → 16）
- ✅ 每次只剪 rank = 1 的線
- ✅ 15 分鐘內完成
- ✅ 看到 "You win!" 和 Flag！

---

## ❌ 失敗情況

- ❌ 剪錯順序 → "Wrong Wire! Kaboomed!"
- ❌ 時間耗盡 → "Time's up! Kaboomed!"
- ❌ 系統已鎖定 → "already detonated! System locked!"

---

## 📂 可用文件

| 文件 | 用途 |
|------|------|
| `COMPLETE_DEFUSE_GUIDE.md` | 完整技術指南（基於原始碼） |
| `defuse_tool.py` | 交互式計算工具 |
| `cutting_sequence_[seed].txt` | 詳細剪線順序文件 |

---

## 💡 關鍵提示

1. **Seed 格式**：10 個 hex 字符（0-9, a-f），不包含 "S/N:"
2. **位置確認**：剪線前確認對應的 GPIO 在電路板上的位置
3. **左上角 GPIO 8**：這是邏輯 Pin 0
4. **右上角 GPIO 0**：這是邏輯 Pin 8
5. **嚴格按順序**：跳過任何步驟都會爆炸！

---

## 🚀 立即開始

```bash
cd csc2025/GrounTruth
python3 defuse_tool.py
```

**輸入你的 Seed，開始拆除炸彈！** 💣➔🏆
