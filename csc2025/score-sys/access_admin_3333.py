#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {
    "x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7",
    "x-admin-pass": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
}
ADMIN_PATH = "/admin_1q8PqqscSiP46w"

print(f"=== Accessing Hidden Admin Path on Port 3333 ===")
try:
    resp = requests.get(f"{BASE_URL}{ADMIN_PATH}", headers=HEADERS)
    print(f"Status: {resp.status_code}")
    print("Response:")
    print(resp.text[:1000])
except Exception as e:
    print(f"Error: {e}")
