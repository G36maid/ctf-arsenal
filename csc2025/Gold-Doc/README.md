# Gold-Doc - CSC2025

## 題目類型
Web Security (XSS + Path Traversal + Privilege Escalation)

## 題目描述
文件管理系統的 Web 應用程式，需要透過多重漏洞鏈取得管理員權限。

## Flag
```
ctfd_f60bed2a9d2ad5f101047068e192824347bbb7c1e4acea983672f1ca5c608a2b
```

## 解題思路

### 1. 資訊洩漏
- 從 HTML 源碼中發現 user1 的憑證資訊
- 登入後發現文件管理功能

### 2. Path Traversal
- 三重 URL 編碼繞過過濾機制：`%25252f` → `%252f` → `%2f` → `/`
- 讀取伺服器檔案：
  - `agent_service.php` - 取得簽章用的 Private Key
  - `db_init.php` - 取得 admin 憑證

### 3. Stored XSS
- 文件標題欄位未過濾 HTML/JavaScript
- 注入惡意腳本竊取 Admin 的操作

### 4. Agent Manipulation
- 使用竊取的 Private Key 簽章惡意請求
- 透過 XSS 觸發 Admin 的 Agent 執行惡意操作
- 竊取 Admin 的 Private Key

### 5. 提權與 Flag
- 使用 Admin 的 Private Key 登入
- 上傳 webshell 或執行特權操作
- 取得 flag

## 關鍵技術
- **XSS**: Stored XSS (文件標題注入)
- **Path Traversal**: 三重 URL 編碼繞過
- **Cryptography**: Private Key 簽章與驗證
- **Privilege Escalation**: 透過 Agent 操控提權

## 使用工具
- Python + requests
- `tools/generate_agent_request.py` - 產生已簽章的 Agent 請求

## 目錄結構
```
Gold-Doc/
├── challenge/          # 原始題目檔案
│   ├── golddoc-.zip    # 題目壓縮包
│   └── 決賽教學題-Golddoc.pdf  # 官方教學文件
├── solution/           # 解題腳本
│   ├── complete_exploit.py  # 完整自動化利用腳本
│   ├── Gold-Doc.md     # 詳細解題筆記
│   └── token           # Flag token
├── tools/              # 工具
│   ├── generate_agent_request.py  # Agent 請求產生器
│   └── exp_template.txt  # XSS payload 模板
└── archive/            # 過時檔案
    └── exploit.py      # 早期版本（需手動操作）
```

## 解題步驟

### 自動化解題
```bash
cd solution
python complete_exploit.py http://target-ip:port
```

### 手動產生 Agent 請求
```bash
cd tools
python generate_agent_request.py \
  --key ./private.pem \
  --op download \
  --target /etc/golddoc-agent/config.json \
  --content-file ./config.json
```

## 利用鏈總結
```
1. HTML 洩漏 user1 憑證
   ↓
2. Path Traversal 讀取 agent_service.php (Private Key)
   ↓
3. Path Traversal 讀取 db_init.php (admin 憑證)
   ↓
4. 使用 Private Key 簽章惡意 Payload
   ↓
5. Stored XSS 觸發 Admin Agent 執行
   ↓
6. 竊取 Admin Private Key
   ↓
7. 登入 Admin 上傳 webshell
   ↓
8. 取得 flag
```

## 參考資料
- Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- XSS: https://owasp.org/www-community/attacks/xss/
- Digital Signature: https://en.wikipedia.org/wiki/Digital_signature
