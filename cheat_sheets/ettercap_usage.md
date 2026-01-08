# Ettercap 快速參考

## 基本指令

### 文字模式 ARP Spoofing
```bash
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.100/
```

### GUI 模式
```bash
sudo ettercap -G
```

### 使用 Filter
```bash
sudo etterfilter modbus_filter.etter -o modbus_filter.ef
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -F modbus_filter.ef
```

### 儲存 PCAP
```bash
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -w capture.pcap
```

## 目標格式

- IP 範圍: `/192.168.1.1-30/`
- 單一 IP: `/192.168.1.100/`
- 完整網段: `/192.168.1.0/24/`
- 指定 Port: `/192.168.1.100/80,443/`
- MAC + IP: `/00:11:22:33:44:55/192.168.1.100/`

## ARP Spoofing 模式

- `arp:remote` - 完整雙向 MITM (推薦)
- `arp:oneway` - 單向 ARP poisoning
- `arp` - 預設模式

## Filter 語法

### 基本結構
```c
if (條件) {
    動作;
}
```

### 常用條件
- `ip.proto == TCP` - TCP 協定
- `tcp.dst == 502` - 目標 Port 502
- `DATA.data + 7 == 0x03` - 檢查 offset 7 的值

### 常用動作
- `msg("text")` - 顯示訊息
- `drop()` - 丟棄封包
- `replace("old", "new")` - 替換內容
- `inject("filename")` - 注入封包

## 常見工控協定 Port

| 協定 | Port |
|------|------|
| Modbus TCP | 502 |
| IEC 60870-5-104 | 2404 |
| DNP3 | 20000 |
| OPC UA | 4840 |
| EtherNet/IP | 44818 |
| S7Comm | 102 |

## Modbus Function Codes

| Code | 功能 | 類型 |
|------|------|------|
| 0x01 | Read Coils | Read |
| 0x02 | Read Discrete Inputs | Read |
| 0x03 | Read Holding Registers | Read |
| 0x04 | Read Input Registers | Read |
| 0x05 | Write Single Coil | Write |
| 0x06 | Write Single Register | Write |
| 0x0F | Write Multiple Coils | Write |
| 0x10 | Write Multiple Registers | Write |

## 實戰 Tips

1. **啟用 IP Forwarding** (必須！)
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

2. **檢查是否成功**
   ```bash
   arp -a  # 在 target 機器上檢查 ARP table
   ```

3. **還原 ARP**
   ```bash
   # Ettercap 會在 Ctrl+C 時自動還原
   # 或手動: arp -d <gateway_ip>
   ```

4. **分析抓到的 PCAP**
   ```bash
   wireshark capture.pcap
   tshark -r capture.pcap -Y "modbus"
   ```

5. **Filter 編譯錯誤**
   - 檢查每行是否有分號 `;`
   - 括號必須成對
   - 字串用雙引號 `"`
