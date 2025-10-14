"""
FMD Server Private Key Client Script

This script authenticates with the FMD server and retrieves the encrypted private key for a user/device.

Usage:
    python fmd_client_key.py --url <server_url> --id <fmd_id> --password <password>

Dependencies:
    pip install requests argon2-cffi
"""
def pad_base64(s):
    return s + '=' * (-len(s) % 4)

import argparse
import base64
from argon2.low_level import hash_secret_raw, Type
import sys
import requests

def hash_password(password: str, salt: str) -> str:
    CONTEXT_STRING_LOGIN = "context:loginAuthentication"
    salt_bytes = base64.b64decode(pad_base64(salt))
    password_bytes = (CONTEXT_STRING_LOGIN + password).encode('utf-8')
    hash_bytes = hash_secret_raw(
        secret=password_bytes,
        salt=salt_bytes,
        time_cost=1,
        memory_cost=131072,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8').rstrip('=')
    encoded = f"$argon2id$v=19$m=131072,t=1,p=4${salt}${hash_b64}"
    return encoded

def get_salt(base_url, fmd_id):
    resp = requests.put(f"{base_url}/api/v1/salt", json={"IDT": fmd_id, "Data": ""})
    if resp.status_code != 200:
        print(f"Failed to get salt: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def get_access_token(base_url, fmd_id, password_hash, session_duration=3600):
    payload = {
        "IDT": fmd_id,
        "Data": password_hash,
        "SessionDurationSeconds": session_duration
    }
    resp = requests.put(f"{base_url}/api/v1/requestAccess", json=payload)
    if resp.status_code != 200:
        print(f"Failed to get access token: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def get_private_key(base_url, access_token):
    resp = requests.put(f"{base_url}/api/v1/key", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get private key: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def main():
    parser = argparse.ArgumentParser(description="FMD Server Private Key Client - Retrieve Encrypted Private Key")
    parser.add_argument('--url', required=True, help='Base URL of the FMD server (e.g. http://localhost:8080)')
    parser.add_argument('--id', required=True, help='FMD ID (username)')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--session', type=int, default=3600, help='Session duration in seconds (default: 3600)')
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    fmd_id = args.id
    password = args.password
    session_duration = args.session

    print("[1] Requesting salt...")
    salt = get_salt(base_url, fmd_id)
    print(f"[2] Hashing password with salt...")
    password_hash = hash_password(password, salt)
    print(f"[3] Requesting access token...")
    access_token = get_access_token(base_url, fmd_id, password_hash, session_duration)
    print(f"[4] Requesting encrypted private key...")
    privkey = get_private_key(base_url, access_token)
    print("\nEncrypted Private Key (base64):")
    print(privkey)

if __name__ == "__main__":
    main()
