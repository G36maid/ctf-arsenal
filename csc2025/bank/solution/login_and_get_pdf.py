#!/usr/bin/env python3
"""
Login to bank and retrieve PDF
"""

import requests
import base64
import re

HOST = "http://192.168.100.127:8051"
IE_UA = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"

session = requests.Session()
session.headers.update({"User-Agent": IE_UA})

data = {"userid": "seacat009", "passwd": "j631R8", "captcha": "田メ５Ѭꙮ҆¿"}

print("[*] Logging in...")
response = session.post(f"{HOST}/app.php", data=data)

if response.status_code != 200:
    print(f"[-] Login failed: HTTP {response.status_code}")
    exit(1)

print("[+] Login successful!")

match = re.search(r'href="data:application/pdf;base64,([^"]+)"', response.text)
if not match:
    print("[-] Could not find PDF in response")
    with open("login_response.html", "w") as f:
        f.write(response.text)
    print("[!] Saved response to login_response.html")
    exit(1)

pdf_b64 = match.group(1)
pdf_data = base64.b64decode(pdf_b64)

with open("bill.pdf", "wb") as f:
    f.write(pdf_data)

print(f"[+] PDF saved to bill.pdf ({len(pdf_data)} bytes)")
print("[*] Next step: crack PDF password (Taiwan National ID format)")
