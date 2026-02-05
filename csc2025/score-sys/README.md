# score-sys - CSC2025

## 題目類型
Web (SQL Injection + PyInstaller Reverse Engineering)

## 題目描述
成績管理系統的 Windows GUI 應用程式，實際上是 PyInstaller 打包的 Python 應用，需要透過 SQL Injection 取得管理員權限。

## Flag
```
CSC{dQ5NYVnXiD-P8_1xxs3b8Ys5ypY4WX4qV3fgZRHMPGU}
```

## 解題思路

### 1. PyInstaller 逆向
- 使用 pyinstxtractor 解包 `score-sys.exe`
- 取得 Python 原始碼和依賴庫
- 分析 API endpoint 和認證機制

### 2. SQL Injection
- API endpoint: `http://192.168.100.110:3333`
- 注入點: `/api/v1/users?user_type=students' UNION ...`
- 洩漏用戶憑證（ID 和密碼雜湊）

### 3. 認證繞過
- 使用 SQL Injection 取得的憑證登入
- Activate Header: `x-activate-code: 8d7a77ae-dac9-4397-afd6-44b92fd5b6f7`

### 4. 特權操作
- 以 Admin 身份創建 "Flag" 科目
- 設置成績觸發 flag 回應
- 取得包含 flag 的 JSON 回應

## 關鍵技術
- **Reverse Engineering**: PyInstaller 解包與分析
- **SQL Injection**: UNION-based injection
- **Web API**: REST API 操作

## 使用工具
- pyinstxtractor - PyInstaller 解包
- Ghidra - 反編譯分析
- Python + requests

## 目錄結構
```
score-sys/
├── challenge/          # 原始題目檔案
│   ├── score-sys.exe   # PyInstaller 打包的應用
│   ├── flag.txt        # Flag
│   └── credentials.txt # 解題過程憑證記錄
├── solution/           # 解題腳本
│   └── solve.py        # 完整解題流程
├── decompile/          # 反編譯結果
│   └── score-sys.exe.c # Ghidra 反編譯
└── archive/            # 中間測試檔案
    ├── score-sys.exe_extracted/  # PyInstaller 解包結果
    ├── score-sys.exe_extracted_duplicate/  # 重複目錄
    ├── exploit_sqli.py # SQL injection 測試
    ├── fuzz_*.py       # Fuzzing 腳本
    └── ...             # 其他測試腳本
```

## 解題步驟

```bash
cd solution
python solve.py
```

## SQL Injection Payload 範例

```sql
-- 洩漏用戶資訊
/api/v1/users?user_type=students' UNION SELECT id, password, role FROM users--

-- 洩漏 Admin ID
/api/v1/users?user_type=teachers' AND role='admin'--
```

## API Endpoints

- `POST /api/v1/login` - 登入
- `GET /api/v1/users` - 取得用戶列表（注入點）
- `POST /api/v1/subjects` - 新增科目
- `POST /api/v1/scores` - 設置成績

## 參考資料
- SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PyInstaller: https://pyinstaller.org/
- pyinstxtractor: https://github.com/extremecoders-re/pyinstxtractor
