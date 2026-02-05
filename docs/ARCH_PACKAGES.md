# Arch Linux 套件安裝清單 (使用 paru)

## 📦 正確的套件名稱

### 核心工具 (extra repo - 高安裝率)
```bash
# Binary Exploitation
paru -S gdb pwndbg gef peda ropper

# ICS/工控情境 (官方指定 Ettercap)
paru -S ettercap          # TUI/CLI 版本
paru -S ettercap-gtk      # GUI 版本 (可選)

# 網路工具
paru -S socat tcpdump nmap

# Python 套件
paru -S python-scapy python-pwntools python-requests python-beautifulsoup4
```

### Ruby Gems
```bash
sudo gem install one_gadget seccomp-tools
```

---

## ✅ 已安裝工具 (無需重新安裝)

| 套件 | 版本 | 備註 |
|------|------|------|
| **python-pwntools** | ✅ 4.15.0 | 核心框架 |
| **ropgadget** | ✅ 7.6 | ROP chain |
| **bettercap** | ✅ 2.41.5 | 現代化 MITM (可替代 Ettercap) |
| **nmap** | ✅ | 網路掃描 |
| **wireshark-cli** (tshark) | ✅ 4.6.2 | 封包分析 |
| **ruby** | ✅ | Ruby runtime |
| **rustc** | ✅ | Rust compiler |
| **python-requests** | ✅ 2.32.5 | HTTP 庫 |

---

## 🎯 一鍵安裝指令

### 最小化安裝 (僅缺失工具)
```bash
paru -S --needed gdb pwndbg ettercap python-scapy socat tcpdump
```

### 完整安裝 (含可選工具)
```bash
paru -S --needed \
    gdb pwndbg gef peda \
    ettercap ropper socat tcpdump \
    python-scapy python-beautifulsoup4

sudo gem install one_gadget seccomp-tools
```

### 含 GUI 工具
```bash
paru -S --needed \
    gdb pwndbg gef peda \
    ettercap ettercap-gtk \
    ropper socat tcpdump \
    python-scapy python-beautifulsoup4 \
    wireshark-qt

sudo gem install one_gadget seccomp-tools
```

---

## 🔧 設定

### 1. 選擇 GDB 增強工具
```bash
# Pwndbg (推薦 CTF)
echo 'source /usr/share/pwndbg/gdbinit.py' > ~/.gdbinit

# 或 GEF (多架構支援)
echo 'source /usr/share/gef/gef.py' > ~/.gdbinit

# 或 PEDA (經典)
echo 'source /usr/share/peda/peda.py' > ~/.gdbinit
```

### 2. 啟用 IP Forwarding (工控題必須)
```bash
sudo sysctl -w net.ipv4.ip_forward=1

# 永久啟用 (可選)
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
```

### 3. 測試安裝
```bash
python3 -c "from pwn import *; print('✓ Pwntools OK')"
python3 -c "from scapy.all import *; print('✓ Scapy OK')"
gdb --version
ettercap --version
gem list | grep -E "one_gadget|seccomp"
```

---

## 🚀 使用自動安裝腳本

```bash
cd ctf-arsenal
bash setup-arch-paru.sh
```

腳本會：
1. 安裝所有缺失工具
2. 詢問是否安裝 GUI (預設跳過)
3. 讓你選擇 GDB 增強工具 (pwndbg/gef/peda)
4. 建立 web shells
5. 啟用 IP forwarding
6. 驗證所有工具

---

## 🎮 TUI/CLI 工具推薦 (你偏好的類型)

### MITM 攻擊
- **ettercap** - 官方指定，CLI 模式流暢
  ```bash
  sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/
  ```
- **bettercap** - 更現代，互動式 TUI (已安裝)
  ```bash
  sudo bettercap -iface eth0
  > net.probe on
  > arp.spoof on
  ```

### 封包分析
- **tshark** - Wireshark CLI (已安裝)
  ```bash
  tshark -i eth0 -f "tcp port 502" -Y modbus
  ```
- **tcpdump** - 經典工具
  ```bash
  tcpdump -i eth0 -w capture.pcap port 502
  ```

### Binary 調試
- **GDB + pwndbg** - 最佳 TUI，彩色輸出
- **GDB + gef** - 多架構支援
- **GDB + peda** - 經典，簡潔

### 其他 TUI 工具 (可選)
```bash
# 進程監控
paru -S btop htop

# 網路監控
paru -S nethogs iftop

# 檔案管理
paru -S ranger nnn

# 十六進位編輯
paru -S hexyl xxd
```

---

## ⚠️ 重要提醒

1. **Ettercap 需要 root**
   ```bash
   sudo ettercap -T ...
   ```

2. **Scapy 需要 root**
   ```bash
   sudo python3 script.py
   ```

3. **工控題必讀**
    ```bash
    cat .agents/skills/ics-traffic/references/ettercap_usage.md
    ```

4. **比賽前測試**
   - 測試 pwntools 模板
   - 測試 ettercap ARP spoofing
   - 確認 IP forwarding 已啟用
