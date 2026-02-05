#!/usr/bin/env python3
"""
Crack PDF password using Taiwan National ID format
Uses multiprocessing for speed
"""

import pikepdf
from multiprocessing import Pool, cpu_count, Manager
from generate_national_id import generate_national_id
import sys

PDF_FILE = "bill.pdf"


def try_password_batch(args):
    """Try a batch of National IDs as PDF passwords"""
    letter_idx, sex_start, sex_end, counter_start, counter_end, found_flag = args

    for sex in range(sex_start, sex_end):
        if found_flag.value:
            return None

        for counter in range(counter_start, counter_end):
            if found_flag.value:
                return None

            nid = generate_national_id(letter_idx, sex, counter)

            try:
                with pikepdf.open(PDF_FILE, password=nid) as pdf:
                    return nid
            except pikepdf.PasswordError:
                continue
            except Exception as e:
                continue

    return None


if __name__ == "__main__":
    print("[*] Starting PDF password cracker...")
    print(f"[*] Using {cpu_count()} worker processes")

    manager = Manager()
    found_flag = manager.Value("i", 0)

    tasks = []
    chunk_size = 10000000 // 20

    for letter_idx in range(26):
        for sex in [1, 2]:
            for chunk_start in range(0, 10000000, chunk_size):
                chunk_end = min(chunk_start + chunk_size, 10000000)
                tasks.append(
                    (letter_idx, sex, sex + 1, chunk_start, chunk_end, found_flag)
                )

    print(f"[*] Total tasks: {len(tasks)}")
    print(f"[*] Estimated total IDs to test: ~520 million")
    print("[*] This may take 10-60 minutes depending on hardware...")
    print("[*] Will stop as soon as password is found\n")

    with Pool(cpu_count()) as pool:
        for i, result in enumerate(pool.imap_unordered(try_password_batch, tasks), 1):
            if result:
                found_flag.value = 1
                pool.terminate()
                print(f"\n[+] PASSWORD FOUND: {result}")
                print(f"[*] Unlocking PDF...")

                with pikepdf.open(PDF_FILE, password=result) as pdf:
                    pdf.save("bill_unlocked.pdf")
                print(f"[+] Unlocked PDF saved to bill_unlocked.pdf")
                sys.exit(0)

            if i % 50 == 0:
                progress = (i / len(tasks)) * 100
                print(
                    f"[*] Progress: {i}/{len(tasks)} tasks ({progress:.1f}%)", end="\r"
                )

    print("\n[-] Password not found")
