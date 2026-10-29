# PKI & Provisioning Starter

This repository is a practical starting point for a PKI and provisioning project focused on secure device identity, certificate lifecycle management, and automation.

## Purpose

PKI and provisioning are foundational for secure IT operations, device management, and cybersecurity workflows. This project is intended to provide a lightweight starter implementation for:

- device registration and identity tracking
- certificate issuance metadata
- provisioning workflow management
- validation and lifecycle status checks

## Recommended direction

The best next step is to scope the project around one concrete use case instead of trying to build a general-purpose PKI platform all at once. A strong starting target is:

- device certificate management for internal infrastructure or IoT environments
- certificate issuance, rotation, and expiration tracking
- provisioning workflows for known device inventories

This repository intentionally starts with the core concepts and a testable service layer so the project can grow into a full CLI or API-based implementation.

## Repository layout

- `src/pki_provisioning/` – main Python package
- `tests/` – unit tests and validation
- `README.md` – project overview and usage
- `pyproject.toml` – Python packaging metadata

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pki-provisioning --help
```

## Example workflow

```bash
pki-provisioning register-device \
  --device-id device-001 \
  --common-name device-001.internal \
  --organization ExampleOrg \
  --environment production

pki-provisioning issue-certificate \
  --device-id device-001 \
  --subject "CN=device-001.internal,O=ExampleOrg" \
  --days 365

pki-provisioning status --device-id device-001
```

## Roadmap

1. Add real X.509 certificate generation using a cryptography library
2. Add persistent storage for device records and issued certificates
3. Add REST API or CLI automation for certificate renewal
4. Add provisioning workflows and lifecycle events
5. Add auditing and revocation support

## Current scope

This version includes a minimal, working model and service layer for:

- registering devices
- creating certificate records
- checking validity windows
- validating the provisioning workflow with tests

It is intentionally small but extensible so the project can evolve into a production-ready PKI or provisioning system.
