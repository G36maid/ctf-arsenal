#!/usr/bin/env python3
"""
Crack bcrypt password hash using multiprocessing
"""

import bcrypt
import sys
from multiprocessing import Pool, cpu_count

# Target hash from users.sqlite3
TARGET_HASH = b"$2a$06$q7vny2yiM0ME28UB2m0/x.5yzMWpBylesMM8VFpSiO59JcbpLj7JC"


def check_password(password):
    """Check if password matches the target hash"""
    try:
        if bcrypt.checkpw(password.encode(), TARGET_HASH):
            return password
    except:
        pass
    return None


def process_chunk(passwords):
    """Process a chunk of passwords"""
    for pwd in passwords:
        result = check_password(pwd.strip())
        if result:
            return result
    return None


def chunk_list(lst, n):
    """Split list into n chunks"""
    chunk_size = len(lst) // n
    for i in range(0, len(lst), chunk_size):
        yield lst[i : i + chunk_size]


if __name__ == "__main__":
    print("[*] Loading password list...")
    with open("passwords.txt", "r") as f:
        passwords = f.readlines()

    total = len(passwords)
    print(f"[*] Total passwords to test: {total}")

    # Use all CPU cores
    num_workers = cpu_count()
    print(f"[*] Using {num_workers} worker processes")

    # Split into chunks
    chunks = list(chunk_list(passwords, num_workers * 4))
    print(f"[*] Split into {len(chunks)} chunks")
    print("[*] Starting brute force (this will take several minutes)...")

    # Process in parallel
    with Pool(num_workers) as pool:
        results = pool.map(process_chunk, chunks)

        for result in results:
            if result:
                print(f"\n[+] PASSWORD FOUND: {result}")
                sys.exit(0)

    print("\n[-] Password not found")
