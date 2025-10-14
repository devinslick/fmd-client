"""
FMD Server Private Key Decryptor

This script takes the encrypted private key (base64) and your password, and decrypts the private key using Argon2id and AES-GCM, matching the FMD web client logic.

Usage:
    python fmd_decrypt_key.py --key <base64_key> --password <password>

Dependencies:
    pip install argon2-cffi cryptography
"""
import argparse
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants from web/fmdcrypto.js
ARGON2_T = 1
ARGON2_P = 4
ARGON2_M = 131072
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16
AES_GCM_IV_SIZE_BYTES = 12
CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

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

def decrypt_private_key(key_b64: str, password: str) -> bytes:
    key_bytes = base64.b64decode(pad_base64(key_b64))
    salt = key_bytes[:ARGON2_SALT_LENGTH]
    iv = key_bytes[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES]
    ciphertext = key_bytes[ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES:]
    aes_key = derive_aes_key(password, salt)
    aesgcm = AESGCM(aes_key)
    privkey_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return privkey_bytes

def main():
    parser = argparse.ArgumentParser(description="FMD Server Private Key Decryptor")
    parser.add_argument('--key', required=True, help='Encrypted private key (base64)')
    parser.add_argument('--password', required=True, help='Password')
    args = parser.parse_args()

    print("[1] Decoding and decrypting private key...")
    privkey_bytes = decrypt_private_key(args.key, args.password)
    print("\nDecrypted Private Key (PEM or DER):")
    print(privkey_bytes.decode(errors='replace'))

if __name__ == "__main__":
    main()
