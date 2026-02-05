#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}
ADMIN_PATH = "/admin_1q8PqqscSiP46w"

print(f"=== Accessing Hidden Admin Path: {ADMIN_PATH} ===")
try:
    resp = requests.get(f"{BASE_URL}{ADMIN_PATH}", headers=HEADERS)
    print(f"Status: {resp.status_code}")
    print("Response:")
    print(resp.text[:1000])

    # Check if it's JSON or HTML
    try:
        data = resp.json()
        print(json.dumps(data, indent=2))
    except:
        pass

except Exception as e:
    print(f"Error: {e}")

# Also check /api/v1/admin_1q8PqqscSiP46w just in case
try:
    resp = requests.get(f"{BASE_URL}/api/v1{ADMIN_PATH}", headers=HEADERS)
    if resp.status_code != 404:
        print(f"\nGET /api/v1{ADMIN_PATH} -> {resp.status_code}")
        print(resp.text[:500])
except:
    pass
