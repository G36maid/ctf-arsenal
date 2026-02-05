# Ground Truth Bomb - 最終使用指南

## 🎯 立即開始

```bash
cd csc2025/GrounTruth
python3 defuse_pi.py
```

輸入裝置顯示的 Seed（10 個 hex 字符），獲得完整剪線順序。

---

## 📍 電路板佈局（以 Raspberry Pi 腳位標記）

```
    ┌───────────────────────┐
    │  u8  │  u0          │  ← 頂部標記
    │  (GPIO 8) │  (GPIO 0)     │
    ├───────────────────────┤
    │  u9-u15               │  ← 右側腳位
    │  (GPIO 9-15)           │  (從上到下)
    ├───────────────────────┤
    │  u15-u9               │  ← 底部腳位
    │  (GPIO 15-16, 右到左)  │
    └───────────────────────┘
```

### 腳位標記對照表

| 標記 | GPIO | 位置 | 說明 |
|--------|------|------|------|
| u8 | 8 | 左上角 | 第一個標記 ⬅ |
| u0 | 0 | 右上角 | 最後一個標記 ➡ |
| u9-u15 | 9-15 | 右側 | 從上到下排列 |
| u15-u9 | 15-16 | 底部 | 從右到左排列 |

---

## ⚡ 剪線順序（以 seed = deadbeef01 為例）

| 步驟 | 標記 | GPIO | 位置 | 說明 |
|-------|--------|------|------|------|
| 1 | u10 | 10 | 右側 | 剪斷 u10 |
| 2 | u14 | 14 | 右側 | 剪斷 u14 |
| 3 | u15 | 15 | 右側 | 剪斷 u15 |
| 4 | u11 | 11 | 右側 | 剪斷 u11 |
| 5 | u22 | 22 | 底部 | 剪斷 u22 |
| 6 | u12 | 12 | 右側 | 剪斷 u12 |
| 7 | u19 | 19 | 底部 | 剪斷 u19 |
| 8 | u8 | 8 | **⬅ 左上角** | 剪斷 u8 |
| 9 | u20 | 20 | 底部 | 剪斷 u20 |
| 10 | u18 | 18 | 底部 | 剪斷 u18 |
| 11 | u17 | 17 | 底部 | 剪斷 u17 |
| 12 | u13 | 13 | 右側 | 剪斷 u13 |
| 13 | u0 | 0 | **➡ 右上角** | 剪斷 u0 |
| 14 | u9 | 9 | 右側 | 剪斷 u9 |
| 15 | u21 | 21 | 底部 | 剪斷 u21 |
| 16 | u16 | 16 | 底部 | 剪斷 u16 → **🎉 WIN!** |

---

## 📋 遊戲規則

### ✅ 成功條件
1. **按步驟順序剪線**：步驟 1 → 2 → 3 → ... → 16
2. **每次只能剪 rank = 1 的線**
3. **正確剪斷後**：所有剩餘線的 rank -1
4. **所有 rank = 0**：顯示 "You win!" 和 Flag！

### ❌ 失敗條件
1. **剪錯順序**（rank ≠ 1）：立即爆炸，顯示 "Wrong Wire!"
2. **時間到**：15 分鐘後自動爆炸，顯示 "Time's up!"
3. **系統已鎖定**：EEPROM 被標記為已爆炸，需要重置

---

## 🚀 操作步驟

### 第 1 步：讀取 Seed
在裝置顯示器上找到：
```
Time Left: mm:ss
S/N: xxxxxxxxxx
oooo xxxx   ← pin 狀態 (o=連接, x=斷開)
```

**Seed 格式**：
- 10 個 16 進制字符（0-9, a-f）
- 從 EEPROM 位址 2-6 讀取（5 bytes）
- 轉換為 "S/N: xxxxxxxxxx" 格式顯示

### 第 2 步：計算剪線順序
```bash
python3 defuse_pi.py
```
輸入 Seed，工具會生成：
- 完整剪線順序（1-16 步驟）
- 快速參考卡
- 詳細說明文件（`cutting_sequence_[seed].txt`）

### 第 3 步：依序剪線
**重要提示**：
1. **找到標記的腳位**：u8（左上角）、u0（右上角）
2. **確認其他腳位**：
   - 右側：u9, u10, u11, u12, u13, u14, u15（從上到下）
   - 底部：u15, u14, u13, u12, u11, u10, u9（從右到左）
3. **按步驟順序剪線**：嚴格遵守 1 → 2 → ... → 16
4. **觀察裝置顯示**：
   - 剪對後 pin 狀態從 'o' 變 'x'
   - 時間倒數每秒更新
   - 剪錯會顯示 "Wrong Wire! Kaboomed!"

### 第 4 步：獲取 Flag
成功後顯示：
```
      You win!
    flag{前半部分 10 個字符}
    flag{後半部分 11 個字符}
```

完整 Flag 格式：`flag{21個字符}`

---

## 💡 關鍵提示

1. **左上角 u8（GPIO 8）**：這是最早要剪的標記之一
2. **右上角 u0（GPIO 0）**：這是最後要剪的標記之一
3. **右側 u9-u15**：7 條線，從上到下
4. **底部 u15-u9**：7 條線，從右到左
5. **每次只剪 rank=1 的線**：跳過任何步驟都會爆炸！

---

## 📂 可用文件

| 文件 | 用途 |
|------|------|
| `defuse_pi.py` | **主工具** - 計算剪線順序（推薦使用） |
| `COMPLETE_DEFUSE_GUIDE.md` | 完整技術指南（基於原始碼） |
| `cutting_sequence_[seed].txt` | 詳細剪線順序文件 |

---

## ⚠️ 常見問題

**Q: 我要輸入 "S/N: xxxxxxxxxx" 嗎？**
A: 不需要！只輸入 10 個 hex 字符（例如：`deadbeef01`）

**Q: 如果剪錯會怎樣？**
A: 立即爆炸，顯示 "Wrong Wire! Kaboomed!"，然後重置系統

**Q: 時間限制多久？**
A: 15 分鐘（900 秒），需要在時間內完成 16 步操作

**Q: 可以跳過步驟嗎？**
A: 不行！必須嚴格按 1 → 2 → 3 → ... → 16 的順序

**Q: 如果系統已經鎖定怎麼辦？**
A: EEPROM 的 `detonatedFlag` 或 `bootedFlag` 被設定，需要清除 EEPROM 重置

---

## 🎯 快速開始命令

```bash
cd csc2025/GrounTruth
python3 defuse_pi.py
```

**輸入你的 Seed，開始拆除炸彈！** 💣➔🏆

---

## 📊 技術細節

### 源碼中的關鍵部分

```c
// Line 25: Pin 配置
const int check_pins[] = {8,9,10,11,12,13,14,15,0,22,21,20,19,18,17,16};
//                 ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑   ↑
//                 u8  u9  u10 u11 u12 u13 u14 u0  u15 u14 u13 u12 u11 u10 u9

// Line 180-261: 雜散種計算（Double SHA512）
void calculate_pins_order(const char *seedString, int pins_order[num_pins]) {
    sha512(seedString, 10, hash);   // 第一個 SHA512
    sha512(hash, 64, hash);          // 第二個 SHA512（對結果再 Hash）
    // 位累積、排序、分配 rank
}

// Line 413-483: 斷開檢測
void check_disconn() {
    // 檢測新斷開的線（LOW → HIGH）
    // 如果任何斷開線的 rank != 1 → 爆炸！
    // 如果所有斷開線的 rank == 1 → 所有 rank -1
    // 如果所有 rank == 0 → WIN！
}
```

### EEPROM 位址配置
```c
#define EEPROM_DETONATED_FLAG_ADDR  0      // 已爆炸標記
#define EEPROM_BOOTED_FLAG_ADDR      1      // 已啟動標記
#define EEPROM_SEED_ADDR             2      // Seed 起始位址（5 bytes）
#define EEPROM_SECRET_ADDR           8      // 加密 Flag（21 bytes）

#define EEPROM_SEED_LENGTH          5
#define EEPROM_SECRET_LENGTH        21
#define EEPROM_SIZE                256
```

---

## ✅ 檢查清單

- [ ] 從裝置顯示器讀取 Seed（10 hex 字符）
- [ ] 執行 `python3 defuse_pi.py` 計算剪線順序
- [ ] 確認電路板上的 u0-u15 標記位置
- [ ] 按照計算的 1-16 步驟順序剪線
- [ ] 每次剪後確認 pin 狀態從 'o' 變 'x'
- [ ] 觀察時間倒數
- [ ] 完成 16 個步驟
- [ ] 看到 "You win!" 和 Flag！🎉

---

## 祝你好運！💣➔🏆
