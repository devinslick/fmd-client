# FMD Server Python Client Scripts

This directory contains Python scripts for interacting with an FMD server, including authentication, key retrieval, and location data decryption.

## Prerequisites
- Python 3.7+
- Install dependencies:
  ```
  pip install requests argon2-cffi cryptography
  ```

## Scripts Overview

### Primary Scripts

These are the most common scripts you will use.

#### `fmd_export.py`
**The main tool for exporting data.** This script performs end-to-end authentication and decryption to download locations and/or pictures, saving them to a directory or a zip archive.

**Usage:**
```
python fmd_client_location.py --url <server_url> --id <fmd_id> --password <password>
```

### 2. `fmd_client_key.py`
Retrieves the encrypted private key for a user/device.

**Usage:**
```
python fmd_client_key.py --url <server_url> --id <fmd_id> --password <password>
```

### 3. `fmd_decrypt_key.py`
Decrypts the encrypted private key using your password.

**Usage:**
```
python fmd_decrypt_key.py --key <base64_key> --password <password>
```
- `<base64_key>`: The encrypted private key (from `fmd_client_key.py`)
- Output: Decrypted private key (PEM or DER)

### 4. `fmd_decrypt_location.py`
Decrypts an encrypted location data blob using your private key.

**Usage:**
```
python fmd_decrypt_location.py --key <private_key_file> --data <base64_location_data>
```
- `<private_key_file>`: Path to your decrypted private key (PEM or DER)
- `<base64_location_data>`: The encrypted location data (from `fmd_client_location.py`)

### 5. `fmd_get_location.py`
**End-to-end automation:** Authenticates, retrieves, and decrypts the latest location data in one step.

**Usage:**
```
python fmd_get_location.py --url <server_url> --id <fmd_id> --password <password>
```
- Output: Decrypted location data as JSON

## Example Workflow
1. Retrieve encrypted location data:
   ```
   python fmd_client_location.py --url https://fmd.example.com --id alice --password secret
   ```
2. Retrieve encrypted private key:
   ```
   python fmd_client_key.py --url https://fmd.example.com --id alice --password secret
   ```
3. Decrypt private key:
   ```
   python fmd_decrypt_key.py --key <base64_key> --password secret > priv.key
   ```
4. Decrypt location data:
   ```
   python fmd_decrypt_location.py --key priv.key --data <base64_location_data>
   ```
5. Or, do it all at once:
   ```
   python fmd_get_location.py --url https://fmd.example.com --id alice --password secret
   ```

## Notes
- All scripts use Argon2id password hashing and AES-GCM/RSA-OAEP encryption, matching the FMD web client.
- For troubleshooting, check the script output for error messages.
- For batch or CSV export, contact the maintainer or extend `fmd_get_location.py`.
