"""
FMD Server Export Data Script

This script authenticates with the FMD server and downloads the exported data as a zip file using the 'export data' function.

Usage:
    python fmd_export_data.py --url <server_url> --id <fmd_id> --password <password> --output <output_zip>

Dependencies:
    pip install requests argon2-cffi
"""
import argparse
import base64
import sys
import requests
from argon2.low_level import hash_secret_raw, Type

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

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

def export_data(base_url, access_token, output_file):
    resp = requests.post(f"{base_url}/api/v1/exportData", json={"IDT": access_token, "Data": "unused"}, stream=True)
    if resp.status_code != 200:
        print(f"Failed to export data: {resp.text}")
        sys.exit(1)
    with open(output_file, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print(f"Exported data saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="FMD Server Export Data Script")
    parser.add_argument('--url', required=True, help='Base URL of the FMD server (e.g. https://fmd.example.com)')
    parser.add_argument('--id', required=True, help='FMD ID (username)')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--output', required=True, help='Output zip file path')
    parser.add_argument('--session', type=int, default=3600, help='Session duration in seconds (default: 3600)')
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    fmd_id = args.id
    password = args.password
    session_duration = args.session
    output_file = args.output

    print("[1] Requesting salt...")
    salt = get_salt(base_url, fmd_id)
    print("[2] Hashing password with salt...")
    password_hash = hash_password(password, salt)
    print("[3] Requesting access token...")
    access_token = get_access_token(base_url, fmd_id, password_hash, session_duration)
    print("[4] Downloading exported data...")
    export_data(base_url, access_token, output_file)

if __name__ == "__main__":
    main()
