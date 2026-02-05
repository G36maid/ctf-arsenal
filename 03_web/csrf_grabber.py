#!/usr/bin/env python3
"""
CSRF Grabber - Extract and use CSRF tokens from forms.

Usage:
    python csrf_grabber.py <target_url> <form_action>

Example:
    python csrf_grabber.py http://target.com/admin http://target.com/admin/action
"""

import requests
from bs4 import BeautifulSoup
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== Configuration =====
session = requests.Session()
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
# session.proxies.update(proxies)
# session.verify = False


def extract_csrf_token(html, token_name="csrf_token"):
    """
    Extract CSRF token from HTML form.
    Tries common field names: csrf_token, _csrf, token, csrf
    """
    patterns = [
        f'name="{token_name}" value="([^"]+)"',
        f'value="([^"]+)"[^>]*name="{token_name}"',
        r'name="csrf_token" value="([^"]+)"',
        r'name="_csrf" value="([^"]+)"',
        r'name="token" value="([^"]+)"',
        r'"csrf":"([^"]+)"',
    ]

    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


def grab_and_use_csrf(form_url, action_url, post_data=None, token_field="csrf_token"):
    """
    Grab CSRF token from form_url and use it in POST to action_url
    """
    print(f"[*] Fetching form from: {form_url}")
    r = session.get(form_url, verify=False)

    if r.status_code != 200:
        print(f"[-] Failed to fetch form: {r.status_code}")
        return None

    # Extract CSRF token
    csrf_token = extract_csrf_token(r.text, token_field)

    if not csrf_token:
        print(f"[-] CSRF token not found in form")
        print("[*] Available form inputs:")
        soup = BeautifulSoup(r.text, "html.parser")
        for inp in soup.find_all("input"):
            print(f"    {inp.get('name')} = {inp.get('value', '[empty]')}")
        return None

    print(f"[+] CSRF Token: {csrf_token[:20]}...")

    # Prepare POST data
    if post_data is None:
        post_data = {}
    post_data[token_field] = csrf_token

    print(f"[*] Posting to: {action_url}")
    r = session.post(action_url, data=post_data, verify=False)

    print(f"[+] Response status: {r.status_code}")
    return r


def list_form_fields(html):
    """List all form fields in HTML"""
    soup = BeautifulSoup(html, "html.parser")
    fields = {}

    for inp in soup.find_all("input"):
        name = inp.get("name")
        value = inp.get("value", "")
        type_ = inp.get("type", "text")
        fields[name] = {"value": value, "type": type_}

    return fields


# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python csrf_grabber.py <form_url> <action_url> [token_field_name]"
        )
        print("\nExample:")
        print(
            "  python csrf_grabber.py http://target.com/login http://target.com/login username=admin&password=pass"
        )
        sys.exit(1)

    form_url = sys.argv[1]
    action_url = sys.argv[2]
    token_field = sys.argv[3] if len(sys.argv) > 3 else "csrf_token"

    print("[*] CSRF Grabber")
    print(f"[*] Form URL: {form_url}")
    print(f"[*] Action URL: {action_url}")
    print(f"[*] Token field: {token_field}")
    print()

    # First, fetch and show available fields
    r_form = session.get(form_url, verify=False)
    fields = list_form_fields(r_form.text)

    print("[*] Available form fields:")
    for name, info in fields.items():
        print(f"    {name}: {info}")
    print()

    # Grab and use CSRF
    post_data = {}
    response = grab_and_use_csrf(form_url, action_url, post_data, token_field)

    if response:
        print("\n[+] Response snippet:")
        print(response.text[:500])
