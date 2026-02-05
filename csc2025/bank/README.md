# Bank - CSC2025

## 題目類型
Web + Crypto (LFI + Password Cracking)

## 題目描述
銀行系統的 Web 應用程式，需要繞過多重防護機制取得管理員權限並下載加密的信用卡帳單。

## Flag
```
(請填入實際 flag)
```

## 解題思路

### 1. 繞過 User-Agent 檢查
- 網站限制只能使用 IE 瀏覽器
- 修改 User-Agent header 繞過檢查

### 2. Local File Inclusion (LFI)
- 利用 LFI 漏洞讀取 `app_source.php` 和 `users.db`
- 從資料庫中取得 bcrypt 雜湊密碼

### 3. 密碼破解
- 分析密碼規則，生成符合條件的密碼字典
- 使用 hashcat 破解 bcrypt 雜湊
- 工具：`solution/crack_password.py`

### 4. 登入並下載 PDF
- 使用破解的密碼登入管理員帳號
- 下載加密的信用卡帳單 PDF

### 5. 破解 PDF 密碼
- PDF 密碼為台灣身分證號碼格式
- 使用自訂的 hashcat 模組生成身分證號碼字典
- 破解 PDF 取得 flag

## 關鍵技術
- **Web 漏洞**: LFI (Local File Inclusion)
- **密碼破解**: hashcat + bcrypt
- **字典生成**: 自訂身分證號碼產生器
- **PDF 破解**: hashcat mode 10500

## 使用工具
- hashcat
- Python + requests
- 自訂 hashcat 模組 (tools/gen_id.so)

## 目錄結構
```
bank/
├── challenge/          # 原始題目檔案
│   ├── app_source.php  # PHP 源碼
│   ├── users.db        # SQLite 資料庫
│   ├── Bank.md         # 題目說明
│   └── Bank_.pdf       # 題目文件
├── solution/           # 解題腳本
│   ├── solve.py        # 主要解題流程
│   ├── crack_password.py
│   ├── crack_pdf.py
│   └── login_and_get_pdf.py
├── tools/              # 工具
│   ├── gen_id.c        # 身分證生成器源碼
│   ├── gen_id.so       # hashcat 插件
│   └── generate_national_id.py
├── archive/            # 臨時檔案（可選保留）
├── hashcat/            # hashcat 工具（佔用空間大）
├── passwords.txt       # 生成的密碼字典（可重新生成）
└── national_ids_common.txt  # 身分證字典（可重新生成）
```

## 解題步驟

### 步驟 1：生成密碼字典
```bash
cd solution
python crack_password.py
```

### 步驟 2：破解 bcrypt 密碼
```bash
hashcat -m 3200 -a 0 hash.txt passwords.txt
```

### 步驟 3：登入並下載 PDF
```bash
python login_and_get_pdf.py
```

### 步驟 4：破解 PDF 密碼
```bash
# 編譯自訂 hashcat 模組
gcc -shared -fPIC -o tools/gen_id.so tools/gen_id.c

# 使用 hashcat 破解
hashcat -m 10500 -a 8 bill.pdf.hash tools/gen_id.so
```

## 注意事項
- `hashcat/`, `passwords.txt`, `national_ids_common.txt` 佔用大量空間（約 800MB）
- 這些檔案可以刪除，需要時可重新生成
- 建議只保留 `tools/gen_id.c` 和 `solution/` 下的腳本

## 參考資料
- hashcat: https://hashcat.net/hashcat/
- bcrypt: https://en.wikipedia.org/wiki/Bcrypt
- 台灣身分證號碼規則: https://zh.wikipedia.org/wiki/中華民國國民身分證
