#!/usr/bin/env python3
"""
Ground Truth Bomb Defuse - Complete Solution
計算炸彈拆除的完整剪線順序
"""

import hashlib


def sha512_double(data):
    """Double SHA512 hash (as used in firmware)"""
    first = hashlib.sha512(data).digest()
    second = hashlib.sha512(first).digest()
    return second


def calculate_pins_order(seed_string):
    """Recreate firmware's calculate_pins_order function"""
    seed_bytes = seed_string.encode("ascii")
    hash_result = sha512_double(seed_bytes)

    pins_order = [0] * 16

    for j in range(64):
        for i in range(8):
            if (hash_result[j] >> i) & 1:
                idx = (j * 8 + i) % 16
                pins_order[idx] += 1

    pairs = []
    for i in range(16):
        pairs.append({"original_index": pins_order[i], "value": i})

    for j1 in range(15):
        for i4 in range(15 - j1):
            if pairs[i4]["original_index"] < pairs[i4 + 1]["original_index"] or (
                pairs[i4]["original_index"] == pairs[i4 + 1]["original_index"]
                and pairs[i4 + 1]["value"] < pairs[i4]["value"]
            ):
                temp_orig = pairs[i4 + 1]["original_index"]
                temp_val = pairs[i4 + 1]["value"]
                pairs[i4 + 1]["original_index"] = pairs[i4]["original_index"]
                pairs[i4 + 1]["value"] = pairs[i4]["value"]
                pairs[i4]["original_index"] = temp_orig
                pairs[i4]["value"] = temp_val

    ranks = [0] * 16
    for i5 in range(16):
        ranks[pairs[i5]["value"]] = i5 + 1

    pins_order = ranks
    return pins_order


def generate_cutting_sequence(seed_string):
    """Generate complete cutting sequence with visual guide"""
    check_pins = [8, 9, 10, 11, 12, 13, 14, 15, 0, 22, 21, 20, 19, 18, 17, 16]
    pins_order = calculate_pins_order(seed_string)

    sequence = []
    for rank in range(1, 17):
        for logical_pin, gpio_pin in enumerate(check_pins):
            if pins_order[logical_pin] == rank:
                position = ""
                if gpio_pin == 8:
                    position = "┌─左上角 (GPIO 8)"
                elif gpio_pin == 0:
                    position = "┌─右上角 (GPIO 0)"
                elif gpio_pin >= 16 and gpio_pin <= 22:
                    position = "底部"
                elif gpio_pin >= 9 and gpio_pin <= 15:
                    position = "右側"

                sequence.append(
                    {
                        "step": rank,
                        "rank": rank,
                        "logical_pin": logical_pin,
                        "gpio_pin": gpio_pin,
                        "position": position,
                        "direction": get_direction(gpio_pin),
                    }
                )
                break

    return sequence


def get_direction(gpio_pin):
    """Get physical position description"""
    if gpio_pin == 8:
        return "TOP-LEFT"
    elif gpio_pin == 0:
        return "TOP-RIGHT"
    elif 9 <= gpio_pin <= 15:
        return "RIGHT-COLUMN"
    elif 16 <= gpio_pin <= 22:
        return "BOTTOM-ROW"
    return "UNKNOWN"


def print_visual_board():
    """Print visual board layout"""
    print("\n" + "=" * 70)
    print("電路板佈局")
    print("=" * 70)
    print("""
    ┌──────────────────────────────┐
    │ GPIO 8  │  GPIO 0        │  ← 頂部標記
    │ (Pin 0)  │  (Pin 8)       │
    ├──────────────────────────────┤
    │  GPIO 9-15               │  ← 右側 7 條線
    │  (Pin 1-7)               │
    ├──────────────────────────────┤
    │  GPIO 22-16               │  ← 底部 7 條線
    │  (Pin 9-15)              │     (從左到右)
    └──────────────────────────────┘
    """)


def print_cutting_sequence(sequence):
    """Print complete cutting sequence"""
    print("\n" + "=" * 70)
    print("完整剪線順序")
    print("=" * 70)
    print(f"{'步驟':<6} {'GPIO':<6} {'邏輯 Pin':<10} {'位置':<20} {'描述'}")
    print("-" * 70)

    for step in sequence:
        print(
            f"{step['step']:<6} {step['gpio_pin']:<6} {step['logical_pin']:<10} "
            f"{step['position']:<20} {step['direction']}"
        )

    print("\n" + "=" * 70)
    print("操作要點")
    print("=" * 70)
    print("1. 按照步驟順序依次剪線")
    print("2. 每剪對一條線，其餘線的 rank -1")
    print("3. 剪錯順序 → 爆炸 ❌")
    print("4. 全部剪對 → 看到 Flag 🎯")


def create_quick_reference(sequence):
    """Create quick reference card"""
    print("\n" + "=" * 70)
    print("快速參考卡")
    print("=" * 70)

    print("\n【頂部 - 關鍵標記】")
    top_pins = [s for s in sequence if s["gpio_pin"] in [8, 0]]
    for pin in top_pins:
        marker = "左上角 ⬅" if pin["gpio_pin"] == 8 else "右上角 ➡"
        print(f"  步驟 {pin['step']:2d}: GPIO {pin['gpio_pin']:2d} {marker}")

    print("\n【右側 - GPIO 9-15】")
    right_pins = [s for s in sequence if 9 <= s["gpio_pin"] <= 15]
    for pin in right_pins:
        print(f"  步驟 {pin['step']:2d}: GPIO {pin['gpio_pin']:2d}")

    print("\n【底部 - GPIO 22-16 (從左到右)】")
    bottom_pins = [s for s in sequence if 16 <= s["gpio_pin"] <= 22]
    for pin in bottom_pins:
        print(f"  步驟 {pin['step']:2d}: GPIO {pin['gpio_pin']:2d}")


def save_to_file(seed_string, sequence):
    """Save sequence to file"""
    filename = f"cutting_sequence_{seed_string}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"Ground Truth Bomb - 剪線順序 (Seed: {seed_string})\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"{'步驟':<6} {'GPIO':<6} {'邏輯 Pin':<10} {'位置':<20}\n")
        f.write("-" * 70 + "\n")
        for step in sequence:
            f.write(
                f"{step['step']:<6} {step['gpio_pin']:<6} {step['logical_pin']:<10} "
                f"{step['position']:<20}\n"
            )

        f.write("\n" + "=" * 70 + "\n")
        f.write("重要提示：\n")
        f.write("=" * 70 + "\n")
        f.write("1. 左上角 GPIO 8 → 這是第一個標記\n")
        f.write("2. 右上角 GPIO 0 → 這是最後一個標記\n")
        f.write("3. 從步驟 1 到 16 依次剪線\n")
        f.write("4. 剪錯任何順序 = 爆炸\n")
        f.write("5. 全部正確 = Flag 顯示\n")

    print(f"\n✅ 完整順序已保存至: {filename}")


def main():
    print("\n" + "🎯" * 35)
    print("Ground Truth Bomb Defuse - 完整解題工具")
    print("🎯" * 35)

    print_visual_board()

    print("=" * 70)
    print("請輸入裝置顯示的 Seed (10 字元 16 進制)")
    print("=" * 70)
    print("\n格式說明：")
    print("  - 裝置會顯示：S/N: xxxxxxxxxx")
    print("  - 輸入那 10 個字元（不包含 S/N:）")
    print("  - 範例：deadbeef01, 1234567890, abcdef0123")

    while True:
        seed = input("\n🔑 請輸入 Seed (或輸入 'quit' 離開): ").strip()

        if seed.lower() == "quit":
            print("\n👋 再見！祝好運！")
            break

        if len(seed) != 10:
            print("❌ 錯誤：Seed 必須是 10 個字元")
            continue

        if not all(c.lower() in "0123456789abcdef" for c in seed):
            print("❌ 錯誤：Seed 只能包含 0-9 和 a-f")
            continue

        print(f"\n✅ 已接收 Seed: {seed}")
        print("🔨 正在計算剪線順序...\n")

        sequence = generate_cutting_sequence(seed)

        print_cutting_sequence(sequence)
        create_quick_reference(sequence)
        save_to_file(seed, sequence)

        print("\n" + "=" * 70)
        print("準備好了嗎？照著順序剪線吧！")
        print("=" * 70)


if __name__ == "__main__":
    main()
