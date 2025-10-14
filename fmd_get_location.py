"""
FMD Server End-to-End Location Retriever

This script automates the full workflow:
- Authenticates with the FMD server using username and password
- Retrieves the encrypted private key and decrypts it
- Retrieves the latest location data and decrypts it
- Prints the decrypted location as JSON

Usage:
    python fmd_get_location.py --url <server_url> --id <fmd_id> --password <password>

Dependencies:
    pip install requests argon2-cffi cryptography
"""
import argparse
import base64
import json
import sys
import requests
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Constants (from web client) ---
ARGON2_T = 1
ARGON2_P = 4
ARGON2_M = 131072
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16
AES_GCM_IV_SIZE_BYTES = 12
RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8
CONTEXT_STRING_LOGIN = "context:loginAuthentication"
CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

def hash_password(password: str, salt: str) -> str:
    salt_bytes = base64.b64decode(pad_base64(salt))
    password_bytes = (CONTEXT_STRING_LOGIN + password).encode('utf-8')
    hash_bytes = hash_secret_raw(
        secret=password_bytes,
        salt=salt_bytes,
        time_cost=ARGON2_T,
        memory_cost=ARGON2_M,
        parallelism=ARGON2_P,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID
    )
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8').rstrip('=')
    encoded = f"$argon2id$v=19$m={ARGON2_M},t={ARGON2_T},p={ARGON2_P}${salt}${hash_b64}"
    return encoded

def derive_aes_key(password: str, salt: bytes) -> bytes:
    password_bytes = (CONTEXT_STRING_ASYM_KEY_WRAP + password).encode('utf-8')
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_T,
        memory_cost=ARGON2_M,
        parallelism=ARGON2_P,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID
    )
    return key

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

def get_private_key_blob(base_url, access_token):
    resp = requests.put(f"{base_url}/api/v1/key", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get private key: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def decrypt_private_key_blob(key_b64: str, password: str) -> bytes:
    key_bytes = base64.b64decode(pad_base64(key_b64))
    salt = key_bytes[:ARGON2_SALT_LENGTH]
    iv = key_bytes[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES]
    ciphertext = key_bytes[ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES:]
    aes_key = derive_aes_key(password, salt)
    aesgcm = AESGCM(aes_key)
    privkey_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return privkey_bytes

def load_private_key_from_bytes(privkey_bytes: bytes):
    try:
        return serialization.load_pem_private_key(privkey_bytes, password=None)
    except ValueError:
        return serialization.load_der_private_key(privkey_bytes, password=None)

def get_location_data_size(base_url, access_token):
    resp = requests.put(f"{base_url}/api/v1/locationDataSize", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get location data size: {resp.text}")
        sys.exit(1)
    return int(resp.json()["Data"])

def get_latest_location_blob(base_url, access_token, index):
    resp = requests.put(f"{base_url}/api/v1/location", json={"IDT": access_token, "Data": str(index)})
    if resp.status_code != 200:
        print(f"Failed to get location: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def decrypt_location_data(private_key, data_b64):
    blob = base64.b64decode(pad_base64(data_b64))
    session_key_packet = blob[:RSA_KEY_SIZE_BYTES]
    iv = blob[RSA_KEY_SIZE_BYTES:RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES]
    ciphertext = blob[RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES:]
    session_key = private_key.decrypt(
        session_key_packet,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext

def main():
    parser = argparse.ArgumentParser(description="FMD Server End-to-End Location Retriever")
    parser.add_argument('--url', required=True, help='Base URL of the FMD server (e.g. https://fmd.example.com)')
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
    print("[2] Hashing password with salt...")
    password_hash = hash_password(password, salt)
    print("[3] Requesting access token...")
    access_token = get_access_token(base_url, fmd_id, password_hash, session_duration)
    print("[4] Retrieving encrypted private key...")
    privkey_blob = get_private_key_blob(base_url, access_token)
    print("[5] Decrypting private key...")
    privkey_bytes = decrypt_private_key_blob(privkey_blob, password)
    private_key = load_private_key_from_bytes(privkey_bytes)
    print("[6] Getting location data size...")
    size = get_location_data_size(base_url, access_token)
    if size == 0:
        print("No location data available.")
        sys.exit(0)
    latest_index = size - 1
    print(f"[7] Retrieving latest location (index {latest_index})...")
    location_blob = get_latest_location_blob(base_url, access_token, latest_index)
    print("[8] Decrypting location data...")
    plaintext = decrypt_location_data(private_key, location_blob)
    print("\nDecrypted Location Data:")
    print(plaintext.decode(errors='replace'))

if __name__ == "__main__":
    main()
