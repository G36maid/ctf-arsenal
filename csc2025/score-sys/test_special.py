#!/usr/bin/env python3
"""
Test for hidden fields and special grade cases
"""

import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}

# Login as Admin
login_data = {
    "user_id": "T001",
    "password": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
    "user_type": "teacher",
}
resp = requests.post(f"{BASE_URL}/api/v1/login", json=login_data, headers=HEADERS)

# Test user fields with special values
test_fields = [
    "flag",
    "secret",
    "token",
    "grade",
    "achievement",
    "reward",
    "special",
    "admin_flag",
    "hidden",
]

print("=== Testing Special Fields ===")
for field in test_fields:
    resp = requests.get(
        f"{BASE_URL}/api/v1/users",
        params={"user_type": "students", "fields": f"student_id,{field}"},
        headers=HEADERS,
    )
    if resp.status_code == 200:
        data = resp.json()
        if data.get("users"):
            for user in data["users"]:
                if field in user and user[field] is not None:
                    print(f"[+] Found {field}: {user}")

# Check if there's a special endpoint for achievements
achievement_endpoints = [
    "/api/v1/achievement",
    "/api/v1/achievements",
    "/api/v1/reward",
    "/api/v1/rewards",
    "/api/v1/grade",
    "/api/v1/grades",
    "/api/v1/student/S001/achievement",
    "/api/v1/student/S001/grade",
]

print("\n=== Testing Achievement Endpoints ===")
for endpoint in achievement_endpoints:
    resp = requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS)
    if resp.status_code != 404:
        print(f"[+] {endpoint} -> {resp.status_code}")
        try:
            print(json.dumps(resp.json(), indent=2))
        except:
            print(resp.text)
