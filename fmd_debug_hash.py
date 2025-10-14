def pad_base64(s):
    return s + '=' * (-len(s) % 4)
"""
FMD Server Password Hash Utility

This script helps you debug the password hashing process for FMD server login.
It prints the salt, the computed hash, and the payload sent to the server.

Usage:
    python fmd_debug_hash.py --url <server_url> --id <fmd_id> --password <password>

Dependencies:
    pip install requests
"""
import argparse
import base64
from argon2.low_level import hash_secret_raw, Type
import requests
import sys

def hash_password(password: str, salt: str) -> str:
    # Try all combinations of hash_len and parallelism
    CONTEXT_STRING_LOGIN = "context:loginAuthentication"
    salt_bytes = base64.b64decode(pad_base64(salt))
    password_bytes = (CONTEXT_STRING_LOGIN + password).encode('utf-8')
    results = []
    for hash_len in (24, 32):
        for parallelism in (1, 4):
            hash_bytes = hash_secret_raw(
                secret=password_bytes,
                salt=salt_bytes,
                time_cost=1,
                memory_cost=131072,
                parallelism=parallelism,
                hash_len=hash_len,
                type=Type.ID
            )
            hash_b64 = base64.b64encode(hash_bytes).decode('utf-8').rstrip('=')
            encoded = f"$argon2id$v=19$m=131072,t=1,p=4${salt}${hash_b64}"
            results.append((hash_len, parallelism, encoded))
    return results

def get_salt(base_url, fmd_id):
    resp = requests.put(f"{base_url}/api/v1/salt", json={"IDT": fmd_id, "Data": ""})
    if resp.status_code != 200:
        print(f"Failed to get salt: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def main():
    parser = argparse.ArgumentParser(description="FMD Server Password Hash Debugger")
    parser.add_argument('--url', required=True, help='Base URL of the FMD server (e.g. http://localhost:8080)')
    parser.add_argument('--id', required=True, help='FMD ID (username)')
    parser.add_argument('--password', required=True, help='Password')
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    fmd_id = args.id
    password = args.password

    print("[1] Requesting salt...")
    salt = get_salt(base_url, fmd_id)
    print(f"Salt: {salt}")
    print(f"[2] Hashing password with salt...")
    hashes = hash_password(password, salt)
    for hash_len, parallelism, password_hash in hashes:
        print(f"Password hash (hash_len={hash_len}, parallelism={parallelism}): {password_hash}")
        print("[3] Example payload for /api/v1/requestAccess:")
        print({
            "IDT": fmd_id,
            "Data": password_hash,
            "SessionDurationSeconds": 3600
        })

if __name__ == "__main__":
    main()
