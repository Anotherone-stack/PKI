# PKI & Provisioning Starter

This project is a lightweight foundation for a PKI and provisioning workflow. It focuses on secure identity management, certificate lifecycle tracking, and simple provisioning rules for devices or services.

## Project goals

- represent device identities clearly
- support certificate issuance metadata
- track validity and revocation lifecycle status
- provide a base for future automation or API work

## Data model

The package includes:

- `DeviceIdentity` – a device or service identity record
- `CertificateTemplate` – certificate issuance rules and constraints
- `CertificateRecord` – issued certificate metadata
- `CertificateManager` – lifecycle manager for device registration and issuance

## CLI commands

- `register-device`
- `issue-certificate`
- `status`

## License

Apache 2.0
