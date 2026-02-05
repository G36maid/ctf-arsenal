# Modbus TCP 快速參考

Modbus TCP/IP 協議快速參考，適用於 CTF ICS 題目。

## 基本資訊

- **預設連接埠**: TCP 502
- **協議**: Modbus TCP (Modbus over TCP/IP)
- **資料格式**: Big-endian (網路位元組序)
- **常見用途**: PLC、RTU、SCADA 系統通訊

## 封包結構

### MBAP Header (7 bytes)

```
+----------------+----------------+
| Transaction ID |  Protocol ID   |
|    (2 bytes)   |   (2 bytes)    |
+----------------+----------------+
|     Length     |   Unit ID      |
|   (2 bytes)    |   (1 byte)     |
+----------------+----------------+
```

**欄位說明**:
- **Transaction ID** (0-1): 請求/回應配對識別碼
- **Protocol ID** (2-3): 固定為 `0x0000` (Modbus)
- **Length** (4-5): 後續位元組數 (Unit ID + PDU)
- **Unit ID** (6): 從設備地址 (0xFF = 廣播)

### PDU (Protocol Data Unit)

```
+----------------+----------------+
| Function Code  |     Data       |
|   (1 byte)     |  (N bytes)     |
+----------------+----------------+
```

## 功能碼 (Function Codes)

### 讀取操作

| 功能碼 | 名稱 | 說明 | 資料型態 |
|--------|------|------|----------|
| 0x01 | Read Coils | 讀取線圈狀態 (DO) | 0/1 |
| 0x02 | Read Discrete Inputs | 讀取離散輸入 (DI) | 0/1 |
| 0x03 | Read Holding Registers | 讀取保持暫存器 | 16-bit |
| 0x04 | Read Input Registers | 讀取輸入暫存器 | 16-bit |

### 寫入操作

| 功能碼 | 名稱 | 說明 | 資料型態 |
|--------|------|------|----------|
| 0x05 | Write Single Coil | 寫入單一線圈 | 0xFF00/0x0000 |
| 0x06 | Write Single Register | 寫入單一暫存器 | 16-bit |
| 0x0F | Write Multiple Coils | 寫入多個線圈 | 位元組陣列 |
| 0x10 | Write Multiple Registers | 寫入多個暫存器 | 16-bit 陣列 |

### 其他

| 功能碼 | 名稱 | 說明 |
|--------|------|------|
| 0x07 | Read Exception Status | 讀取異常狀態 |
| 0x08 | Diagnostics | 診斷 |
| 0x0B | Get Comm Event Counter | 獲取通訊事件計數 |
| 0x11 | Report Server ID | 報告伺服器 ID |
| 0x17 | Read/Write Multiple Registers | 讀寫多個暫存器 |

## Exception Codes (錯誤碼)

當功能碼 MSB = 1 (例如 0x83 = 0x03 錯誤)，表示異常回應。

| 錯誤碼 | 名稱 | 說明 |
|--------|------|------|
| 0x01 | Illegal Function | 不支援的功能碼 |
| 0x02 | Illegal Data Address | 非法資料地址 |
| 0x03 | Illegal Data Value | 非法資料值 |
| 0x04 | Server Device Failure | 伺服器設備故障 |
| 0x05 | Acknowledge | 已確認 (長時間處理) |
| 0x06 | Server Device Busy | 伺服器忙碌 |
| 0x08 | Memory Parity Error | 記憶體同位檢查錯誤 |
| 0x0A | Gateway Path Unavailable | 閘道路徑不可用 |
| 0x0B | Gateway Target Failed | 閘道目標回應失敗 |

## 常用操作範例

### 讀取 Holding Registers (0x03)

**請求格式**:
```
MBAP Header:
  Transaction ID: 0x0001
  Protocol ID: 0x0000
  Length: 0x0006 (6 bytes following)
  Unit ID: 0x01

PDU:
  Function Code: 0x03
  Starting Address: 0x0000 (2 bytes)
  Quantity: 0x000A (10 registers)
```

**Hex**: `00 01 00 00 00 06 01 03 00 00 00 0A`

**回應格式**:
```
MBAP Header:
  Transaction ID: 0x0001
  Protocol ID: 0x0000
  Length: 0x0017 (23 bytes = 1 + 1 + 20 + 1)
  Unit ID: 0x01

PDU:
  Function Code: 0x03
  Byte Count: 0x14 (20 bytes = 10 registers * 2)
  Register Values: [10 * 16-bit values]
```

### 寫入單一線圈 (0x05)

**請求格式**:
```
MBAP Header:
  Transaction ID: 0x0002
  Protocol ID: 0x0000
  Length: 0x0006
  Unit ID: 0x01

PDU:
  Function Code: 0x05
  Output Address: 0x0000
  Output Value: 0xFF00 (ON) 或 0x0000 (OFF)
```

**Hex (ON)**: `00 02 00 00 00 06 01 05 00 00 FF 00`

**回應**: 回傳相同的請求 (echo)

### 寫入多個暫存器 (0x10)

**請求格式**:
```
MBAP Header:
  Transaction ID: 0x0003
  Protocol ID: 0x0000
  Length: 0x000B (11 bytes)
  Unit ID: 0x01

PDU:
  Function Code: 0x10
  Starting Address: 0x0000
  Quantity of Registers: 0x0002 (2 registers)
  Byte Count: 0x04 (4 bytes)
  Registers Value: 0x000A 0x0102 (例如)
```

**Hex**: `00 03 00 00 00 0B 01 10 00 00 00 02 04 00 0A 01 02`

**回應格式**:
```
PDU:
  Function Code: 0x10
  Starting Address: 0x0000
  Quantity of Registers: 0x0002
```

## 位址範圍 (典型配置)

**注意**: Modbus 位址有 0-based 和 1-based 兩種慣例！

| 資料型態 | 協議位址 (0-based) | 傳統位址 (1-based) |
|----------|-------------------|-------------------|
| Coils (DO) | 0x0000 - 0xFFFF | 00001 - 09999 |
| Discrete Inputs (DI) | 0x0000 - 0xFFFF | 10001 - 19999 |
| Input Registers | 0x0000 - 0xFFFF | 30001 - 39999 |
| Holding Registers | 0x0000 - 0xFFFF | 40001 - 49999 |

**CTF 中常用位址**:
- `0x0000` - 第一個暫存器/線圈
- `0x0001` - 第二個
- `0x0064` (100) - 常見測試位址

## Wireshark / tshark 過濾

```bash
# 顯示所有 Modbus
modbus

# 只顯示寫入操作
modbus.func_code == 0x05 || modbus.func_code == 0x06 || modbus.func_code == 0x0f || modbus.func_code == 0x10

# 特定暫存器
modbus.reference_num == 0x0000

# 異常回應
modbus.func_code >= 0x80

# 導出欄位
tshark -r capture.pcap -Y "modbus" -T fields -e modbus.trans_id -e modbus.func_code -e modbus.reference_num -e modbus.word_cnt
```

## Python 封包構造 (Scapy)

```python
from scapy.all import *

# Modbus TCP Read Holding Registers
mbap = struct.pack('>HHHB', 1, 0, 6, 1)  # Trans ID, Proto, Len, Unit
pdu = struct.pack('>BHH', 0x03, 0x0000, 10)  # FC, Start, Qty

packet = IP(dst="192.168.1.100")/TCP(dport=502)/Raw(load=mbap+pdu)
send(packet)

# Modbus TCP Write Single Coil
mbap = struct.pack('>HHHB', 2, 0, 6, 1)
pdu = struct.pack('>BHH', 0x05, 0x0000, 0xFF00)  # ON

packet = IP(dst="192.168.1.100")/TCP(dport=502)/Raw(load=mbap+pdu)
send(packet)
```

## 攻擊場景

### 場景 1: 監聽暫存器讀寫

```bash
# 使用 tshark
sudo tshark -i eth0 -f "tcp port 502" -Y "modbus.func_code == 0x03 || modbus.func_code == 0x10"

# 使用 Scapy
sudo python modbus_sniffer.py
```

### 場景 2: 重放寫入命令

```bash
# 1. 捕獲寫入封包
sudo tcpdump -i eth0 -w modbus_capture.pcap port 502

# 2. 重放
sudo python modbus_replay.py modbus_capture.pcap 192.168.1.100
```

### 場景 3: 阻止寫入操作 (MITM)

```bash
# 使用 Ettercap filter
sudo etterfilter modbus_block_writes.etter -o modbus_block.ef
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -F modbus_block.ef
```

### 場景 4: 修改暫存器值

```bash
# 注入自訂寫入命令
sudo python modbus_inject.py 192.168.1.100 0x01 0x10 0x0000 "0A0B"
```

## 常見 PLC 品牌與 Modbus

| 品牌 | 支援 Modbus | 預設連接埠 | 備註 |
|------|-------------|-----------|------|
| Schneider Electric | ✓ | 502 | Modicon 系列 |
| Siemens | ✓ | 502 | S7-1200/1500 支援 |
| Allen-Bradley | ✓ | 502 | 透過 gateway |
| ABB | ✓ | 502 | |
| Mitsubishi | ✓ | 502 | |
| Omron | ✓ | 502 | |

## 參考資料

- [Modbus 官方規範](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus TCP 規範](https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)
- [Wikipedia - Modbus](https://en.wikipedia.org/wiki/Modbus)

## CTF 提示

1. **位址從 0 開始** (協議層面)
2. **寫入值**: 線圈用 `0xFF00` (ON) / `0x0000` (OFF)
3. **暫存器數量限制**: 通常 1-125 個暫存器
4. **Transaction ID 不重要** 在單次連線中，可以隨意設定
5. **Unit ID**: 如果不確定，試 `0x01` 或 `0xFF` (廣播)
