# PKI
PKI and Provisioning are two important concepts in IT, cybersecurity, networking, and device management.

## Current status

This project now includes:

- real X.509 certificate issuance with `cryptography`
- a lightweight FastAPI service for certificate operations
- a file-backed JSON store for devices and issued certificates
- CLI access for registration and issuance flows

## API endpoints

- `GET /health`
- `GET /api/health`
- `POST /api/devices`
- `POST /api/certificates`
- `GET /api/certificates/{device_id}/validity`
- `GET /api/certificates`
- `GET /api/status`

## Example payloads

Register a device:

```json
{
  "device_id": "device-001",
  "common_name": "device-001.internal",
  "organization": "ExampleOrg",
  "environment": "production"
}
```

Issue a certificate:

```json
{
  "device_id": "device-001",
  "subject": "CN=device-001.internal,O=ExampleOrg",
  "validity_days": 365,
  "key_size": 2048
}
```

## Data persistence

The repository currently uses a simple file-backed JSON store at `pki_store.json` to retain device registrations and certificate records across process restarts. This keeps the system operational without prematurely introducing a database layer.

## Next planned step

The next evolution is to add richer issuance metadata and then upgrade the storage layer to a real database-backed provisioning workflow when operational needs justify it.
