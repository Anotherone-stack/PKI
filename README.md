# PKI
PKI and Provisioning are two important concepts in IT, cybersecurity, networking, and device management.

## Current direction

This repository has been advanced into a real certificate-generation starter using the `cryptography` library. The system models device identities and issues X.509 certificates with configurable validity periods, subject fields, and SAN entries.

## What is included

- `DeviceIdentity` model for registering devices
- `CertificateTemplate` model for issuance requirements
- `CertificateRecord` with issued certificate metadata
- `CertificateManager` for device registration and certificate issuance
- real X.509 certificate generation using `cryptography`
- CLI entrypoints for device registration and certificate issuance
- automated tests for certificate generation and validation

## Example usage

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pki-provisioning register-device \
  --device-id device-001 \
  --common-name device-001.internal \
  --organization ExampleOrg \
  --environment production

pki-provisioning issue-certificate \
  --device-id device-001 \
  --subject "CN=device-001.internal,O=ExampleOrg" \
  --days 365 \
  --output-certificate /tmp/device-001.crt \
  --output-private-key /tmp/device-001.key
```

## Project goals

- issue real X.509 certificates instead of placeholder values
- validate certificate expiration and lifecycle state
- provide a strong base for later API or provisioning automation work
