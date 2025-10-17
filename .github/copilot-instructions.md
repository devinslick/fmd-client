# FMD Client Copilot Instructions

## Project Overview
This is a Python client library for the FMD (Find My Device) server - an open-source, self-hostable alternative to commercial device tracking services. The client handles authentication, encrypted key management, and location/picture data decryption.

## Architecture

### Core Components
- **`fmd_api.py`**: Core API library (`FmdApi` class) - handles ALL server communication, authentication, and cryptographic operations
- **`fmd_client.py`**: Main user-facing CLI tool for batch exports (locations/pictures to CSV/ZIP)
- **`debugging/`**: Standalone scripts for testing individual API workflows (not dependencies of main client)

### Data Flow
1. **Authentication**: Salt retrieval → Argon2id password hashing → Access token acquisition → Private key retrieval & decryption
2. **Data Retrieval**: API requests use access token → Returns encrypted blobs (base64-encoded)
3. **Decryption**: Two-layer encryption (RSA-OAEP for session key, AES-GCM for data)

## Cryptographic Standards
All crypto operations MUST match the FMD web client specification:
- **Password hashing**: Argon2id (m=131072, t=1, p=4, 32-byte output)
- **Context strings**: `"context:loginAuthentication"` (login) and `"context:asymmetricKeyWrap"` (key decryption)
- **Data decryption**: RSA-OAEP (SHA-256) wraps AES-GCM session key; first 384 bytes = encrypted session key, next 12 bytes = IV, remainder = ciphertext
- **Base64 padding**: Always use `_pad_base64()` helper for server responses (missing padding)

## Key Patterns

### API Request Structure
All API endpoints use PUT requests with `{"IDT": <id_or_token>, "Data": <payload>}` format. Response is `{"Data": <result>}`. See `_make_api_request()` in `fmd_api.py`.

### Location/Picture Handling
- Location blobs decrypt to JSON with fields: `time`, `provider`, `bat`, `lon`, `lat`
- Picture blobs decrypt to base64 strings (often with data URI prefix like `data:image/png;base64,`)
- Always split on comma and take the last segment: `decrypted_text.split(',')[-1]`

### Client Usage Pattern
The `FmdApi` class performs full authentication on initialization - private key is ready immediately after `FmdApi(url, id, password)`. No separate auth step needed.

## Development Workflows

### Testing Individual API Calls
Use scripts in `debugging/` to test specific workflows:
- `fmd_get_location.py`: End-to-end test (auth + decrypt one location)
- `fmd_export_data.py`: Test server's native export ZIP endpoint

### Running the Main Client
```powershell
python fmd_client.py --url https://fmd.example.com --id alice --password secret --output export.zip --locations --pictures
```
Supports `--locations [N]` and `--pictures [N]` where N = number of most recent items (omit N for all).

### Dependencies
Install via: `pip install requests argon2-cffi cryptography`
See `setup.py` for package distribution configuration.

## Common Pitfalls
- **Base64 padding**: Server returns unpadded base64 - always use `_pad_base64()` before decoding
- **Picture format**: Pictures are double-encoded (encrypted blob → base64 string → image bytes)
- **API endpoints**: All use PUT, not GET/POST (except `/api/v1/exportData` which is POST)
- **Error handling**: Wrap API calls in try/except for `FmdApiException` - contains original request context
- **Empty/invalid blobs**: Server may return very small blobs (2-4 bytes) for missing/corrupted data - validate blob size before decryption (minimum 396 bytes: 384 RSA + 12 IV)
