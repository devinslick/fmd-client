"""
FMD Server Location Data Decryptor

This script takes the decrypted private key (PEM or DER) and the encrypted location data (base64), and decrypts the location data using RSA-OAEP and AES-GCM, matching the FMD web client logic.

Usage:
    python fmd_decrypt_location.py --key <private_key_file> --data <base64_location_data>

Dependencies:
    pip install cryptography
"""
import argparse
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants from fmdcrypto.js
AES_GCM_IV_SIZE_BYTES = 12
RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

def load_private_key(filename):
    with open(filename, 'rb') as f:
        key_data = f.read()
    try:
        # Try PEM first
        return serialization.load_pem_private_key(key_data, password=None)
    except ValueError:
        # Try DER
        return serialization.load_der_private_key(key_data, password=None)

def decrypt_location_data(private_key, data_b64):
    blob = base64.b64decode(pad_base64(data_b64))
    session_key_packet = blob[:RSA_KEY_SIZE_BYTES]
    iv = blob[RSA_KEY_SIZE_BYTES:RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES]
    ciphertext = blob[RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES:]
    # Decrypt session key with RSA-OAEP
    session_key = private_key.decrypt(
        session_key_packet,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt ciphertext with AES-GCM
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext

def main():
    parser = argparse.ArgumentParser(description="FMD Server Location Data Decryptor")
    parser.add_argument('--key', required=True, help='Path to decrypted private key (PEM or DER)')
    parser.add_argument('--data', required=True, help='Encrypted location data (base64)')
    args = parser.parse_args()

    print("[1] Loading private key...")
    private_key = load_private_key(args.key)
    print("[2] Decrypting location data...")
    plaintext = decrypt_location_data(private_key, args.data)
    print("\nDecrypted Location Data:")
    print(plaintext.decode(errors='replace'))

if __name__ == "__main__":
    main()
