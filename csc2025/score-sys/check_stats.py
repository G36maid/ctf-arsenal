#!/usr/bin/env python3
"""
Quick script to check statistics and scores
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
print("Login:", resp.status_code)
if resp.status_code != 200:
    print("Login failed:", resp.text)
    exit(1)

# Check statistics
resp = requests.get(f"{BASE_URL}/api/v1/statistics", headers=HEADERS)
print("\n=== Statistics ===")
print("Status:", resp.status_code)
print(json.dumps(resp.json(), indent=2))

# Check Alice's scores
resp = requests.get(f"{BASE_URL}/api/v1/student/S001/scores", headers=HEADERS)
print("\n=== Alice's Scores ===")
print("Status:", resp.status_code)
print(json.dumps(resp.json(), indent=2))

# Calculate Alice's average
scores_data = resp.json()
if "scores" in scores_data and scores_data["scores"]:
    total = sum(s["score"] for s in scores_data["scores"])
    count = len(scores_data["scores"])
    avg = total / count
    print(f"\nAlice's Average: {avg:.2f}")
    print(f"Total Subjects: {count}")
