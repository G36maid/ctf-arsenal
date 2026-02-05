#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def try_add_subject(user_id, password, subject_name):
    # Login
    login_data = {"user_id": user_id, "password": password, "user_type": "teacher"}
    session = requests.Session()
    resp = session.post(f"{BASE_URL}/api/v1/login", json=login_data, headers=HEADERS)
    if resp.status_code != 200:
        print(f"Login failed for {user_id}")
        return

    print(f"\nUser: {user_id}, Subject: {subject_name}")

    # Try 1: JSON with 'name'
    resp = session.post(
        f"{BASE_URL}/api/v1/subject", json={"name": subject_name}, headers=HEADERS
    )
    print(f"  JSON 'name': {resp.status_code} - {resp.text}")

    # Try 2: JSON with 'subject'
    resp = session.post(
        f"{BASE_URL}/api/v1/subject", json={"subject": subject_name}, headers=HEADERS
    )
    print(f"  JSON 'subject': {resp.status_code} - {resp.text}")

    # Try 3: JSON with 'subject_name'
    resp = session.post(
        f"{BASE_URL}/api/v1/subject",
        json={"subject_name": subject_name},
        headers=HEADERS,
    )
    print(f"  JSON 'subject_name': {resp.status_code} - {resp.text}")

    # Try 4: Form data 'name'
    resp = session.post(
        f"{BASE_URL}/api/v1/subject", data={"name": subject_name}, headers=HEADERS
    )
    print(f"  Form 'name': {resp.status_code} - {resp.text}")


print("=== Testing with T001 (Admin) ===")
try_add_subject("T001", "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM", "FlagSubject1")

print("\n=== Testing with T002 (Dr. Williams) ===")
try_add_subject("T002", "teacher_69be364ed259", "FlagSubject2")
