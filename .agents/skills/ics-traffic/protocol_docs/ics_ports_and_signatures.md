# ICS 協議連接埠與特徵

## 常見 ICS 協議連接埠

| 協議 | 連接埠 | 傳輸層 | 說明 |
|------|--------|--------|------|
| **Modbus TCP** | 502 | TCP | 工業自動化標準協議 |
| **IEC 60870-5-104** | 2404 | TCP | 電力系統 SCADA |
| **DNP3** | 20000 | TCP/UDP | 電力/水務 SCADA |
| **OPC UA** | 4840 | TCP | 工業物聯網 |
| **S7comm** | 102 | TCP | Siemens PLC (S7-300/400) |
| **S7comm-plus** | 102 | TCP | Siemens PLC (S7-1200/1500) |
| **Ethernet/IP** | 44818 | TCP/UDP | Allen-Bradley/Rockwell |
| **BACnet** | 47808 | UDP | 建築自動化 |
| **Profinet** | 34962-34964 | TCP/UDP | Siemens 工業乙太網 |
| **Mitsubishi MELSEC** | 5007 | TCP | Mitsubishi PLC |
| **Omron FINS** | 9600 | TCP/UDP | Omron PLC |
| **PCWorx** | 1962 | TCP | Phoenix Contact PLC |
| **CIP** | 2222 | TCP | Common Industrial Protocol |
| **HART-IP** | 5094 | TCP/UDP | Highway Addressable Remote Transducer |

## Wireshark Display Filters

```bash
# Modbus
modbus

# IEC 104
iec60870_104

# DNP3
dnp3

# OPC UA
opcua

# S7comm
s7comm

# Ethernet/IP
enip || cip

# BACnet
bacnet || bacapp

# 多協議 (ICS 總覽)
modbus || iec60870_104 || dnp3 || opcua || s7comm || enip
```

## tshark 快速過濾

```bash
# 提取 Modbus 封包
tshark -r capture.pcap -Y "modbus" -w modbus_only.pcap

# 顯示 IEC 104 控制命令
tshark -r capture.pcap -Y "iec60870_104.typeid == 100 || iec60870_104.typeid == 101"

# DNP3 統計
tshark -r capture.pcap -Y "dnp3" -T fields -e dnp3.al.func | sort | uniq -c

# 識別協議
tshark -r capture.pcap -qz io,phs

# 連接埠統計
tshark -r capture.pcap -qz endpoints,tcp
```

## 協議特徵簽章

### Modbus TCP
- 連接埠: 502
- 協議 ID: 前 2 bytes 為 Transaction ID，bytes 3-4 固定 `00 00`
- 典型模式: `xx xx 00 00 00 xx yy zz ...`

### IEC 104
- 連接埠: 2404
- Start byte: `0x68` (104 decimal)
- 典型 APDU: `68 xx xx xx xx ...`

### DNP3
- 連接埠: 20000
- Start bytes: `0x05 0x64`
- 典型封包: `05 64 xx ...`

### S7comm
- 連接埠: 102
- TPKT Header: `03 00` + length
- COTP: `02 F0 80` (connection)
- 典型模式: `03 00 00 xx 02 ...`

### OPC UA
- 連接埠: 4840
- Message type: `HEL` (Hello), `ACK`, `OPN`, etc.
- Binary protocol (UACP)

## tcpdump 過濾器

```bash
# Modbus
sudo tcpdump -i eth0 -w modbus.pcap port 502

# IEC 104
sudo tcpdump -i eth0 -w iec104.pcap port 2404

# DNP3
sudo tcpdump -i eth0 -w dnp3.pcap port 20000

# OPC UA
sudo tcpdump -i eth0 -w opcua.pcap port 4840

# S7comm
sudo tcpdump -i eth0 -w s7comm.pcap port 102

# 所有 ICS
sudo tcpdump -i eth0 -w ics_all.pcap 'port 502 or port 2404 or port 20000 or port 4840 or port 102 or port 44818'
```

## nmap 掃描 ICS 協議

```bash
# Modbus
nmap -p 502 --script modbus-discover 192.168.1.0/24

# S7comm
nmap -p 102 --script s7-info 192.168.1.0/24

# BACnet
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Ethernet/IP
nmap -p 44818 --script enip-info 192.168.1.0/24

# 通用掃描
nmap -p 102,502,2404,4840,20000,44818,47808 192.168.1.0/24
```

## CTF 識別技巧

1. **查看連接埠**: 502 → Modbus, 2404 → IEC 104, 20000 → DNP3
2. **檢查 magic bytes**: `68` → IEC 104, `05 64` → DNP3
3. **Wireshark 自動識別**: 開啟 PCAP 看 Protocol 欄位
4. **流量行為**: 週期性輪詢 → Modbus/IEC104, 事件驅動 → DNP3
5. **封包大小**: Modbus 通常小 (<100 bytes), OPC UA 較大

## 參考資源

- [ICS Protocol Library](https://www.digitalbond.com/tools/basecamp/ics-protocol-library/)
- [Wireshark ICS Protocols](https://wiki.wireshark.org/Protocols)
- [nmap NSE Scripts](https://nmap.org/nsedoc/)
