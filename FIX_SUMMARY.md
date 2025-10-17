# Fix Summary: Blob Size Validation

## Problem
The client was failing with the error:
```
Warning: failed to decrypt or parse location: Ciphertext length must be equal to key size.
```

## Root Cause
The FMD server was returning **invalid/empty location blobs** (only 2 bytes: `0xdfad`) instead of properly encrypted data. When the client tried to decrypt these tiny blobs, it attempted to:
1. Extract the first 384 bytes as the RSA session key packet
2. But the blob was only 2 bytes long

This caused the RSA decryption to fail because it expected exactly 384 bytes.

## Solution

### 1. Added Blob Size Validation (`fmd_api.py`)
Before attempting decryption, validate that the blob is at least 396 bytes (384 RSA + 12 IV):

```python
def decrypt_data_blob(self, data_b64: str) -> bytes:
    blob = base64.b64decode(_pad_base64(data_b64))
    
    # Check if blob is large enough to contain encrypted data
    min_size = RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES
    if len(blob) < min_size:
        raise FmdApiException(
            f"Blob too small for decryption: {len(blob)} bytes (expected at least {min_size} bytes). "
            f"This may indicate empty/invalid data from the server."
        )
    # ... rest of decryption
```

### 2. Improved Error Messages (`fmd_client.py`)
- Added indexed error messages (e.g., "Skipping location 0 - ...")
- Added summary counts of skipped items
- Applied to both directory and ZIP export modes

### 3. Updated Documentation
Added to `.github/copilot-instructions.md`:
- Note about empty/invalid blob detection (minimum 396 bytes)
- Explanation of the two-byte blob issue

## Testing
Verified fix with:
- Valid data: Successfully exported location with coordinates
- Invalid/small blobs: Now provides clear error message instead of cryptic RSA error

## Why This Happens
Possible reasons for 2-byte blobs from server:
- Location data was never uploaded for that device
- Corruption or deletion on server side
- Server returning placeholder/sentinel values for missing data
