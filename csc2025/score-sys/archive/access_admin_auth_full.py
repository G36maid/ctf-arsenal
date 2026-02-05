#!/usr/bin/env python3
import requests

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {
    "x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7",
    "x-admin-pass": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
}
ADMIN_PATH = "/admin_1q8PqqscSiP46w"

print(f"=== Accessing Hidden Admin Path with Header ===")
resp = requests.get(f"{BASE_URL}{ADMIN_PATH}", headers=HEADERS)
print(f"Status: {resp.status_code}")
with open("traceback_admin.html", "w") as f:
    f.write(resp.text)
print("Saved to traceback_admin.html")
