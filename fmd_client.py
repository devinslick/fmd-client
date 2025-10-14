def pad_base64(s):
    return s + '=' * (-len(s) % 4)
"""
FMD Server Remote Client Script

This script authenticates with the FMD server and retrieves the latest location data for a user/device.

Usage:
    python fmd_client.py --url <server_url> --id <fmd_id> --password <password>

Dependencies:
    pip install requests
"""
import argparse
import base64
from argon2.low_level import hash_secret_raw, Type
import json
import sys
import requests


def hash_password(password: str, salt: str) -> str:
    # Use Argon2id with context string, matching web client
    CONTEXT_STRING_LOGIN = "context:loginAuthentication"
    # Always decode the salt from base64 for Argon2 input, pad if needed
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
    # Use the original salt string (not re-encoded) in the encoded hash
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


def get_location_data_size(base_url, access_token):
    resp = requests.put(f"{base_url}/api/v1/locationDataSize", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get location data size: {resp.text}")
        sys.exit(1)
    return int(resp.json()["Data"])


def get_latest_location(base_url, access_token, index):
    resp = requests.put(f"{base_url}/api/v1/location", json={"IDT": access_token, "Data": str(index)})
    if resp.status_code != 200:
        print(f"Failed to get location: {resp.text}")
        sys.exit(1)
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="FMD Server Remote Client - Retrieve Latest Location Data")
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
    print(f"[4] Getting location data size...")
    size = get_location_data_size(base_url, access_token)
    if size == 0:
        print("No location data available.")
        sys.exit(0)
    latest_index = size - 1
    print(f"[5] Retrieving latest location (index {latest_index})...")
    location = get_latest_location(base_url, access_token, latest_index)
    print("\nLatest Location Data:")
    print(json.dumps(location, indent=2))

if __name__ == "__main__":
    main()
