#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}

# Login as T002 (Dr. Williams)
login_data = {
    "user_id": "T002",
    "password": "teacher_69be364ed259",
    "user_type": "teacher",
}
session = requests.Session()
resp = session.post(f"{BASE_URL}/api/v1/login", json=login_data, headers=HEADERS)
print(f"Login T002: {resp.status_code}")


def add_subject(name):
    data = {"name": name}
    resp = session.post(f"{BASE_URL}/api/v1/subject", json=data, headers=HEADERS)
    print(f"Add Subject '{name}': {resp.status_code} - {resp.text}")


subjects_to_try = [
    "Flag",
    "flag",
    "Secret",
    "secret",
    "Key",
    "key",
    "CSC",
    "CTF",
    "Admin",
    "Root",
]

print("\n=== Adding Special Subjects ===")
for sub in subjects_to_try:
    add_subject(sub)

print("\n=== Checking Subjects List ===")
resp = session.get(f"{BASE_URL}/api/v1/subjects", headers=HEADERS)
print(json.dumps(resp.json(), indent=2))

# Check if Alice has scores for these new subjects (maybe auto-populated?)
print("\n=== Checking Alice's Scores Again ===")
resp = session.get(f"{BASE_URL}/api/v1/student/S001/scores", headers=HEADERS)
print(json.dumps(resp.json(), indent=2))
