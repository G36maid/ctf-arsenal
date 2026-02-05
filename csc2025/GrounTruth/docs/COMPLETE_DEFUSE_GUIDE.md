# Ground Truth Bomb - 完整拆除指南

## 核心邏輯

### 1. 系統配置
```c
const int check_pins[] = {8,9,10,11,12,13,14,15,0,22,21,20,19,18,17,16};
// 索引 0-15 對應邏輯 Pin 0-15
// 值對應實際 GPIO 腳位
```

### 2. Pin 分配（邏輯 Pin → GPIO）

| 邏輯 Pin | GPIO | 位置 | 說明 |
|----------|------|------|------|
| 0 | 8 | 左上角 | 第一個標記 |
| 1-7 | 9-15 | 右側 | 從上到下 |
| 8 | 0 | 右上角 | 第二個標記 |
| 9-15 | 22-16 | 底部 | 從左到右 |

### 3. 遊戲規則

#### 成功條件
1. **按 rank 順序剪線**：rank 1 → rank 2 → ... → rank 16
2. 每次正確剪斷後，所有剩餘 pins 的 rank 減 1
3. **所有 rank = 0** → 顯示 Flag！

#### 失敗條件
1. **剪錯順序**（rank ≠ 1）→ 立即爆炸
2. **時間耗盡**（15 分鐘）→ 爆炸
3. **之前已經爆炸過**→ 系統鎖定，無法再玩

---

## 完整操作流程

### 第 1 步：讀取 Seed

在裝置顯示器上看到：
```
Time Left: mm:ss
S/N: xxxxxxxxxx
oooo xxxx   ← pin 狀態 (o=連接, x=斷開)
oooo xxxx
```

**Seed 格式**：
- 10 個 16 進制字符（0-9, a-f）
- 從 EEPROM 位址 2-6 讀取（5 bytes）
- 顯示為 "S/N: xxxxxxxxxx"

### 第 2 步：計算剪線順序

使用腳本計算：
```bash
cd csc2025/GrounTruth
python3 defuse_tool.py
```

輸入 seed，獲得完整剪線順序（1-16 步）。

### 第 3 步：依序剪線

**關鍵規則**：
```
初始狀態：
  pins_order = [rank1, rank2, ..., rank16]  (範圍 1-16)

剪線循環：
  1. 找到 rank = 1 的邏輯 Pin
  2. 剪斷該 Pin 對應的 GPIO
  3. ✅ 如果正確 → 所有 rank -1
     - 原 rank 1 變成 0
     - 原 rank 2 變成 1（下次剪）
     - 原 rank 3 變成 2（下次後下次）
  4. ❌ 如果錯誤（剪 rank ≠ 1）→ 爆炸！

  繼續直到所有 rank = 0 → WIN！
```

### 第 4 步：查看 Flag

成功後顯示：
```
      You win!
    flag{前半部分}
  flag{後半部分}
```

---

## 詳細示例

假設 Seed = `deadbeef01`，計算結果：

### 初始狀態
```
pins_order = [15, 3, 8, 12, 16, 4, 13, 5, 14, 6, 9, 1, 7, 10, 2, 11]

第 1 輪（找 rank = 1）：
  → 邏輯 Pin 11, GPIO 20, 底部
  → 剪斷 GPIO 20
  → 所有 rank -1: [14, 2, 7, 11, 15, 3, 12, 4, 13, 5, 8, 0, 6, 9, 1, 10]

第 2 輪（找 rank = 1，現在是原 rank 2）：
  → 邏輯 Pin 2, GPIO 10, 右側
  → 剪斷 GPIO 10
  → 所有 rank -1: [13, 1, 6, 10, 14, 2, 11, 3, 12, 4, 7, 0, 5, 8, 0, 9, 11]

第 3 輪（找 rank = 1，現在是原 rank 3）：
  → 邏輯 Pin 6, GPIO 14, 右側
  → 剪斷 GPIO 14
  → 所有 rank -1...

... 重複 16 輪，直到全部為 0 → WIN！
```

---

## 電路板視覺指南

```
    ┌─────────────────────────┐
    │ GPIO 8  │  GPIO 0      │  ← 頂部標記點
    │ (Pin 0) │  (Pin 8)     │
    ├─────────────────────────┤
    │ GPIO 9-15              │  ← 右側 7 條線（上到下）
    │ (Pin 1-7)              │
    ├─────────────────────────┤
    │ GPIO 22-16             │  ← 底部 7 條線（左到右）
    │ (Pin 9-15)             │
    └─────────────────────────┘
```

### GPIO 物理位置
- **GPIO 8**：左上角（Pin 0）
- **GPIO 0**：右上角（Pin 8）
- **GPIO 9-15**：右側（Pin 1-7），從上到下
- **GPIO 22-16**：底部（Pin 9-15），從左到右

---

## 源代碼關鍵函數

### `calculate_pins_order()` (Line 180-261)
```c
void calculate_pins_order(const char *seedString, int pins_order[num_pins]) {
    // 1. Double SHA512
    sha512(seedString, 10, hash);   // 第一個 SHA512
    sha512(hash, 64, hash);          // 第二個 SHA512（結果再 Hash）

    // 2. 累積位到 pins_order
    for (int i = 0; i < 64; i++) {      // 64 bytes
        for (int j = 0; j < 8; j++) {    // 8 bits per byte
            int pin_idx = (i * 8 + j) % 16;
            if (hash[i] & (1 << j)) {
                pins_order[pin_idx]++;
            }
        }
    }

    // 3. 排序並分配 rank (1-16)
    // 使用氣泡排序，按值降序，相同值按原始索引升序
    // 最小值 = rank 1（最先剪）
    // 最大值 = rank 16（最後剪）
}
```

### `check_disconn()` (Line 413-483)
```c
void check_disconn() {
    // 1. 檢測新斷開的線（從 LOW 變 HIGH）
    // 2. 如果任何斷開線的 rank != 1 → 爆炸！
    // 3. 如果所有斷開線的 rank == 1 → 所有 rank -1
    // 4. 如果所有 rank == 0 → WIN！
}
```

### `win()` (Line 392-411)
```c
void win() {
    // 顯示 "You win!"
    // 顯示 flag（前半和後半）
    // 無限循環，持續顯示
}
```

---

## 重要提示

### ✅ DO（要做的事）
1. **先計算**：獲取完整剪線順序後再開始剪
2. **按順序剪**：嚴格遵守 1 → 2 → 3 → ... → 16
3. **確認位置**：剪前確認對應的 GPIO 位置
4. **觀察顯示**：注意 "Wrong Wire!" 或 "Kaboomed!" 訊息
5. **時間管理**：15 分鐘內完成，不要急但也不要拖延

### ❌ DON'T（不要做的事）
1. **不要亂剪**：剪錯任何一步就會爆炸
2. **不要跳過**：必須嚴格按 rank 順序
3. **不要重試太快**：爆炸後需要重置系統
4. **不要忽略顯示**："Wrong Wire!" 表示你剪錯了
5. **不要忘記時間**：時間到會自動爆炸

---

## 常見問題

**Q: 我可以猜嗎？**
A: 不行！Seed 是隨機的，每個裝置都不同，必須計算。

**Q: 剪錯了會怎樣？**
A: 立即顯示 "Wrong Wire! Kaboomed!"，然後重置系統，需要重新開始。

**Q: 可以只剪部分嗎？**
A: 可以，但要按正確順序。剪對的線會減少其他 rank，直到全部為 0。

**Q: Flag 是什麼格式？**
A: 21 個字符，格式為 `flag{...}`，分兩行顯示（每行 10 和 11 字符）。

**Q: 如果系統已經鎖定怎麼辦？**
A: EEPROM 的 `detonatedFlag` 或 `bootedFlag` 被設定，需要清除 EEPROM 重置。

**Q: 時間限制多久？**
A: 15 分鐘（900 秒），每秒更新顯示。

---

## 計算工具使用

### 方法 1：交互式工具
```bash
python3 defuse_tool.py
# 輸入 seed
# 獲得完整順序
# 查看快速參考卡
# 保存詳細文件
```

### 方法 2：手動計算
如果腳本不可用：
1. 使用任意 Double SHA512 計算器
2. 實現位累積邏輯（見源代碼）
3. 實現氣泡排序（降序）
4. 分配 rank 1-16

---

## 成功檢查清單

- [ ] 從顯示器讀取 Seed（10 hex 字符）
- [ ] 使用 defuse_tool.py 計算剪線順序
- [ ] 確認電路板上的 GPIO 位置
- [ ] 理解邏輯 Pin → GPIO 的映射
- [ ] 按計算的 1-16 順序剪線
- [ ] 每次剪後確認顯示 "o" → "x"
- [ ] 觀察倒數時間
- [ ] 完成 16 個步驟
- [ ] 看到 "You win!" 和 Flag！🎉

---

## 源代碼參考

### EEPROM 位址分配
```c
#define EEPROM_DETTONATED_FLAG_ADDR  0
#define EEPROM_BOOTED_FLAG_ADDR      1
#define EEPROM_SEED_ADDR           2    // 5 bytes (addresses 2-6)
#define EEPROM_SECRET_ADDR          8    // 21 bytes (addresses 8-28)

#define EEPROM_SEED_LENGTH          5
#define EEPROM_SECRET_LENGTH        21
#define EEPROM_SIZE                256
```

### 全局變數
```c
int pins_order[16];           // 每個 Pin 的 rank (1-16)
int prev_pin_states[16];     // 之前的 Pin 狀態（檢測斷開）
String pinStatesRow1;         // 第一行 Pin 狀態顯示（Pin 0-7）
String pinStatesRow2;         // 第二行 Pin 狀態顯示（Pin 8-15）
unsigned long totalSeconds;    // 剩餘秒數（初始 900）
```

---

## 祝你好運！💣➔🏆

**記住：耐心、精確、按順序剪！**
