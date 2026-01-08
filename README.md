# CTF Arsenal - 競賽工具箱

針對 **5 小時 Jeopardy CTF** 設計的離線工具箱，重點支援：
- **Binary Exploitation (Pwn/Rev)**
- **工業控制情境 (ICS) - Ettercap MITM**
- Web, Crypto, Forensics, Misc

## 快速開始

### 1. 安裝
```bash
cd ctf-arsenal
bash scripts/setup-arch-paru.sh  # Arch Linux + paru
# 或使用 scripts/setup.sh (通用版本)
```

### 2. 啟用環境
```bash
source venv/bin/activate
```

### 3. 設定 GDB
```bash
cp 01_bin_exploit/gdb_init/gdbinit-pwndbg ~/.gdbinit
```

## 目錄結構

```
ctf-arsenal/
├── 00_templates/              ⭐ 最重要！比賽開始直接複製修改
│   ├── pwn_basic.py          → Pwntools 基礎模板 (Local/GDB/Remote)
│   ├── pwn_rop.py            → ROP chain + ret2libc 模板
│   ├── solve.rs              → Rust 多執行緒暴力破解
│   └── web_requests.py       → Python Requests 模板
│
├── 01_bin_exploit/
│   ├── gdb_init/             → GDB 設定檔 (pwndbg/gef)
│   ├── gadgets/              → 常用 shellcode
│   └── tools/                → 特殊工具
│
├── 02_ics_traffic/           ⚠️ 工控情境題必看
│   ├── mitm_scripts/
│   │   ├── arp_spoof.py      → Scapy ARP Spoofing
│   │   ├── modbus_filter.etter → Ettercap Modbus filter
│   │   └── iec104_filter.etter → Ettercap IEC 104 filter
│   ├── scapy_scripts/
│   │   ├── modbus_sniffer.py → Modbus 封包分析
│   │   └── modbus_inject.py  → Modbus 封包注入
│   └── protocol_docs/         → 工控協定文件
│
├── 03_web/
│   ├── wordlists/            → rockyou.txt, SecLists
│   ├── payloads/             → SQL injection, XSS
│   └── webshells/            → PHP, JSP, ASPX shells
│
├── 04_crypto/
│   ├── rsa_tool/             → RsaCtfTool
│   └── classic.py            → 經典密碼學
│
├── 05_forensics/
├── 06_misc/
│
├── static_bins/              💾 救命用靜態二進位檔
│   ├── busybox-x86_64
│   ├── nmap (需自行下載)
│   └── socat (需自行下載)
│
└── cheat_sheets/             📖 快速參考
    ├── ettercap_usage.md     ⚠️ Ettercap 必讀
    ├── gdb_cheatsheet.md
    └── linux_commands.md
```

## 重要提醒

### 工控情境題準備 (官方明確提示)

**必須熟悉 Ettercap！**

1. **啟用 IP Forwarding**
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```

2. **ARP Spoofing 基本指令**
   ```bash
   sudo ettercap -T -i eth0 -M arp:remote /target_ip/ /gateway_ip/
   ```

3. **使用 Filter**
   ```bash
   sudo etterfilter modbus_filter.etter -o modbus_filter.ef
   sudo ettercap -T -i eth0 -M arp:remote /target/ /gateway/ -F modbus_filter.ef
   ```

4. **快速參考**
   - 詳見 `cheat_sheets/ettercap_usage.md`
   - Modbus Port: `502`
   - IEC 104 Port: `2404`
   - DNP3 Port: `20000`

### Pwn 題快速流程

1. **複製模板**
   ```bash
   cp 00_templates/pwn_basic.py solve.py
   ```

2. **檢查保護**
   ```bash
   checksec ./vuln
   ```

3. **找 offset**
   ```python
   python solve.py
   ```

4. **GDB 調試**
   ```bash
   python solve.py GDB
   ```

5. **打遠端**
   ```bash
   python solve.py REMOTE 192.168.1.100 1337
   ```

### 常用工具速查

| 類別 | 工具 | 用途 |
|------|------|------|
| **Pwn** | pwntools | Exploit 開發 |
| | ROPgadget/ropper | ROP chain |
| | one_gadget | 快速 shell |
| **ICS** | Ettercap | MITM 攻擊 |
| | Scapy | 封包操作 |
| | Wireshark | 流量分析 |
| **Web** | requests | HTTP 操作 |
| | sqlmap | SQL Injection |
| **Crypto** | RsaCtfTool | RSA 攻擊 |
| | CyberChef | 編解碼 |

## 工具安裝清單

### Arch Linux 套件
```bash
sudo pacman -S python-pwntools gdb pwndbg gef ropgadget ropper \
    ettercap wireshark-qt nmap socat tcpdump \
    ruby python-requests python-scapy
```

### Ruby Gems
```bash
sudo gem install one_gadget seccomp-tools
```

### Python (venv)
```bash
pip install pwntools requests beautifulsoup4 scapy pycryptodome
```

## 比賽當天檢查清單

- [ ] `git clone` 此 repo 到比賽機器
- [ ] 執行 `bash scripts/setup-arch-paru.sh` 安裝工具
- [ ] 測試 `python 00_templates/pwn_basic.py` (或 `uv run python 00_templates/pwn_basic.py`)
- [ ] 確認 GDB 正常 (pwndbg/gef)
- [ ] 測試 Ettercap: `sudo ettercap -T -i eth0 -M arp`
- [ ] 確認 IP forwarding: `sudo sysctl -w net.ipv4.ip_forward=1`
- [ ] 瀏覽 `cheat_sheets/` 快速複習

## 常見問題

### GDB 沒有載入 pwndbg/gef
```bash
echo 'source /usr/share/pwndbg/gdbinit.py' >> ~/.gdbinit
```

### Ettercap 需要 root
```bash
sudo ettercap ...
```

### Scapy 需要 root
```bash
sudo python3 script.py
```

### 找不到 rockyou.txt
```bash
cd 03_web/wordlists/SecLists
tar -xzf Passwords/Leaked-Databases/rockyou.txt.tar.gz
```

## 進階參考資源

### 工控安全
- Modbus 協定: `02_ics_traffic/protocol_docs/`
- Ettercap 官方文件: https://www.ettercap-project.org/
- ICS CTF Writeups: https://github.com/neutrinoguy/awesome-ics-writeups

### Binary Exploitation
- Pwntools 文件: https://docs.pwntools.com/
- Pwndbg GitHub: https://github.com/pwndbg/pwndbg
- ROPEmporium: https://ropemporium.com/

### Web Security
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- OWASP: https://owasp.org/

## 授權

教育與 CTF 競賽使用。工具版權歸原作者所有。
