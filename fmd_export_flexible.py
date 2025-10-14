"""
FMD Server Data Export Script (Flexible)

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

def get_locations(base_url, access_token):
    resp = requests.post(f"{base_url}/api/v1/locations", json={"IDT": access_token, "Data": ""})
    if resp.status_code != 200:
        print(f"Failed to get locations: {resp.text}")
        sys.exit(1)
    return resp.json()

def get_pictures(base_url, access_token):
    resp = requests.post(f"{base_url}/api/v1/pictures", json={"IDT": access_token, "Data": ""})
    if resp.status_code != 200:
        print(f"Failed to get pictures: {resp.text}")
        sys.exit(1)
    return resp.json()

def save_locations_csv(locations_json, out_path):
    header = "Date,Provider,Battery Percentage,Longitude,Latitude\n"
    lines = [header]
    for locationJSON in locations_json:
        loc = eval(locationJSON) if isinstance(locationJSON, str) else locationJSON
        # Fallback: try to parse as dict if not already
        date = loc.get('time')
        provider = loc.get('provider')
        bat = loc.get('bat')
        lon = loc.get('lon')
        lat = loc.get('lat')
        lines.append(f"{date},{provider},{bat},{lon},{lat}\n")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def save_pictures(pictures_json, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for idx, pic_b64 in enumerate(pictures_json):
        with open(os.path.join(out_dir, f"{idx}.png"), 'wb') as f:
            f.write(base64.b64decode(pad_base64(pic_b64)))

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

    locations_json = None
    pictures_json = None
    if include_locations:
        print("[4] Downloading locations...")
        locations_json = get_locations(base_url, access_token)
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
                for locationJSON in locations_json:
                    loc = eval(locationJSON) if isinstance(locationJSON, str) else locationJSON
                    date = loc.get('time')
                    provider = loc.get('provider')
                    bat = loc.get('bat')
                    lon = loc.get('lon')
                    lat = loc.get('lat')
                    csv_buf.write(f"{date},{provider},{bat},{lon},{lat}\n")
                zf.writestr('locations.csv', csv_buf.getvalue())
            if include_pictures and pictures_json is not None:
                for idx, pic_b64 in enumerate(pictures_json):
                    zf.writestr(f'pictures/{idx}.png', base64.b64decode(pad_base64(pic_b64)))
        print(f"Exported data saved to {output_path}")
    else:
        print(f"[6] Writing to directory: {output_path}")
        os.makedirs(output_path, exist_ok=True)
        if include_locations and locations_json is not None:
            save_locations_csv(locations_json, os.path.join(output_path, 'locations.csv'))
        if include_pictures and pictures_json is not None:
            save_pictures(pictures_json, os.path.join(output_path, 'pictures'))
        print(f"Exported data saved to {output_path}")

if __name__ == "__main__":
    main()
