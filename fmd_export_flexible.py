"""
FMD Server Data Export Script

This script authenticates with the FMD server and downloads locations and/or pictures, saving them as a zip or directory.

Usage:
    python fmd_export_flexible.py --url <server_url> --id <fmd_id> --password <password> --output <output_path> [--locations] [--pictures]

Dependencies:
    pip install requests argon2-cffi
"""
import argparse
import base64
import sys
import os
import requests
from argon2.low_level import hash_secret_raw, Type
import zipfile
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Constants from fmd_get_location.py ---
CONTEXT_STRING_LOGIN = "context:loginAuthentication"

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

def get_all_locations(base_url, access_token):
    # Get total number of locations
    resp = requests.put(f"{base_url}/api/v1/locationDataSize", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get location data size: {resp.text}")
        sys.exit(1)
    size = int(resp.json()["Data"])
    print(f"Found {size} locations to download.")
    # Fetch each location by index
    locations = []
    for i in range(size):
        print(f"  - Downloading location {i+1}/{size}...")
        resp = requests.put(f"{base_url}/api/v1/location", json={"IDT": access_token, "Data": str(i)})
        if resp.status_code == 200:
            locations.append(resp.json()["Data"])
        else:
            print(f"Warning: Failed to get location at index {i}: {resp.text}")
    return locations

def get_pictures(base_url, access_token):
    # This endpoint likely returns all pictures in a single bulk response.
    resp = requests.put(f"{base_url}/api/v1/pictures", json={"IDT": access_token, "Data": ""})
    if resp.status_code != 200:
        print(f"Warning: Failed to get pictures: {resp.text}. The endpoint may not exist or requires a different method.")
        return []
    return resp.json()

def get_private_key_blob(base_url, access_token):
    resp = requests.put(f"{base_url}/api/v1/key", json={"IDT": access_token, "Data": "unused"})
    if resp.status_code != 200:
        print(f"Failed to get private key: {resp.text}")
        sys.exit(1)
    return resp.json()["Data"]

def decrypt_private_key_blob(key_b64: str, password: str) -> bytes:
    ARGON2_SALT_LENGTH = 16
    AES_GCM_IV_SIZE_BYTES = 12
    CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"
    key_bytes = base64.b64decode(pad_base64(key_b64))
    salt = key_bytes[:ARGON2_SALT_LENGTH]
    iv = key_bytes[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES]
    ciphertext = key_bytes[ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES:]
    password_bytes = (CONTEXT_STRING_ASYM_KEY_WRAP + password).encode('utf-8')
    aes_key = hash_secret_raw(
        secret=password_bytes, salt=salt, time_cost=1, memory_cost=131072,
        parallelism=4, hash_len=32, type=Type.ID
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext, None)

def load_private_key_from_bytes(privkey_bytes: bytes):
    try:
        return serialization.load_pem_private_key(privkey_bytes, password=None)
    except ValueError:
        return serialization.load_der_private_key(privkey_bytes, password=None)

def decrypt_data_blob(private_key, data_b64):
    RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8
    AES_GCM_IV_SIZE_BYTES = 12
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
    return aesgcm.decrypt(iv, ciphertext, None)

def save_locations_csv(locations_response, out_path, private_key):
    header = "Date,Provider,Battery Percentage,Longitude,Latitude\n"
    lines = [header]
    location_list = locations_response
    for location_blob in location_list:
        loc = None
        try:            
            decrypted_bytes = decrypt_data_blob(private_key, location_blob)
            loc = json.loads(decrypted_bytes)
        except Exception as e:
            print(f"Warning: failed to decrypt or parse location: {e}")
            continue

        if not loc:
            continue

        date = loc.get('time', 'N/A')
        provider = loc.get('provider', 'N/A')
        bat = loc.get('bat', 'N/A')
        lon = loc.get('lon', 'N/A')
        lat = loc.get('lat', 'N/A')
        lines.append(f"{date},{provider},{bat},{lon},{lat}\n")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def save_pictures(pictures_response, out_dir, private_key):
    os.makedirs(out_dir, exist_ok=True)
    picture_list = pictures_response
    for idx, pic_blob in enumerate(picture_list):
        try:
            if pic_blob:
                decrypted_payload_bytes = decrypt_data_blob(private_key, pic_blob)
                # The decrypted payload is likely a base64 string, possibly with a data URI prefix.
                decrypted_text = decrypted_payload_bytes.decode('utf-8')
                base64_data = decrypted_text.split(',')[-1]
                image_bytes = base64.b64decode(pad_base64(base64_data))
                with open(os.path.join(out_dir, f"{idx}.png"), 'wb') as f:
                    f.write(image_bytes)
        except Exception as e:
            print(f"Warning: failed to decrypt or write picture {idx}: {e}")

def main():
    parser = argparse.ArgumentParser(description="FMD Server Data Export Script (Flexible)")
    parser.add_argument('--url', required=True, help='Base URL of the FMD server (e.g. https://fmd.example.com)')
    parser.add_argument('--id', required=True, help='FMD ID (username)')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--output', required=True, help='Output .zip file or directory')
    parser.add_argument('--locations', action='store_true', help='Include locations')
    parser.add_argument('--pictures', action='store_true', help='Include pictures')
    parser.add_argument('--session', type=int, default=3600, help='Session duration in seconds (default: 3600)')
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    fmd_id = args.id
    password = args.password
    session_duration = args.session
    output_path = args.output
    include_locations = args.locations
    include_pictures = args.pictures

    if not (include_locations or include_pictures):
        print("Nothing to export: specify --locations and/or --pictures")
        sys.exit(1)

    print("[1] Requesting salt...")
    salt = get_salt(base_url, fmd_id)
    print("[2] Hashing password with salt...")
    password_hash = hash_password(password, salt)
    print("[3] Requesting access token...")
    access_token = get_access_token(base_url, fmd_id, password_hash, session_duration)
    
    print("[3a] Retrieving encrypted private key...")
    privkey_blob = get_private_key_blob(base_url, access_token)
    print("[3b] Decrypting private key...")
    privkey_bytes = decrypt_private_key_blob(privkey_blob, password)
    private_key = load_private_key_from_bytes(privkey_bytes)

    locations_json = None
    pictures_json = None
    if include_locations:
        print("[4] Downloading locations...")
        locations_json = get_all_locations(base_url, access_token)
    if include_pictures:
        print("[5] Downloading pictures...")
        pictures_json = get_pictures(base_url, access_token)

    is_zip = output_path.lower().endswith('.zip')
    if is_zip:
        print(f"[6] Writing to zip: {output_path}")
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            if include_locations and locations_json is not None:
                import io
                csv_buf = io.StringIO()
                header = "Date,Provider,Battery Percentage,Longitude,Latitude\n"
                csv_buf.write(header)
                location_list = locations_json
                for location_blob in location_list:
                    if not location_blob: continue
                    loc = None
                    try:
                        decrypted_bytes = decrypt_data_blob(private_key, location_blob)
                        loc = json.loads(decrypted_bytes)
                    except Exception as e:
                        print(f"Warning: failed to decrypt or parse location for zip: {e}")
                        continue

                    if not loc:
                        continue
                    date = loc.get('time', 'N/A')
                    provider = loc.get('provider', 'N/A')
                    bat = loc.get('bat', 'N/A')
                    lon = loc.get('lon', 'N/A')
                    lat = loc.get('lat', 'N/A')
                    csv_buf.write(f"{date},{provider},{bat},{lon},{lat}\n")
                zf.writestr('locations.csv', csv_buf.getvalue())
            if include_pictures and pictures_json is not None:
                picture_list = pictures_json
                for idx, pic_blob in enumerate(picture_list):
                    if pic_blob:
                        try:
                            decrypted_payload_bytes = decrypt_data_blob(private_key, pic_blob)
                            decrypted_text = decrypted_payload_bytes.decode('utf-8')
                            base64_data = decrypted_text.split(',')[-1]
                            image_bytes = base64.b64decode(pad_base64(base64_data))
                            zf.writestr(f'pictures/{idx}.png', image_bytes)
                        except Exception as e:
                            print(f"Warning: failed to decrypt or write picture {idx} for zip: {e}")
        print(f"Exported data saved to {output_path}")
    else:
        print(f"[6] Writing to directory: {output_path}")
        os.makedirs(output_path, exist_ok=True)
        if include_locations and locations_json is not None:
            save_locations_csv(locations_json, os.path.join(output_path, 'locations.csv'), private_key)
        if include_pictures and pictures_json is not None:
            save_pictures(pictures_json, os.path.join(output_path, 'pictures'), private_key)
        print(f"Exported data saved to {output_path}")

if __name__ == "__main__":
    main()
