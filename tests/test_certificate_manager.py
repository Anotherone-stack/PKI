from __future__ import annotations

import argparse
import json
from pathlib import Path

from .certificate_manager import CertificateManager
from .models import CertificateTemplate, DeviceIdentity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PKI and provisioning starter CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register-device", help="register a device identity")
    register.add_argument("--device-id", required=True)
    register.add_argument("--common-name", required=True)
    register.add_argument("--organization", required=True)
    register.add_argument("--environment", default="production")

    issue = subparsers.add_parser("issue-certificate", help="issue a real X.509 certificate")
    issue.add_argument("--device-id", required=True)
    issue.add_argument("--subject", required=True)
    issue.add_argument("--days", type=int, default=365)
    issue.add_argument("--key-size", type=int, default=2048)
    issue.add_argument("--output-certificate", default=None)
    issue.add_argument("--output-private-key", default=None)

    status = subparsers.add_parser("status", help="show certificate status")
    status.add_argument("--device-id", required=True)

    return parser


def main() -> None:
    manager = CertificateManager()
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "register-device":
        device = manager.register_device(
            DeviceIdentity(
                device_id=args.device_id,
                common_name=args.common_name,
                organization=args.organization,
                environment=args.environment,
            )
        )
        print(json.dumps({"device": device.__dict__}, indent=2))
        return

    if args.command == "issue-certificate":
        if args.device_id not in manager._devices:
            raise ValueError(f"Unknown device: {args.device_id}. Register it first.")

        cert = manager.create_certificate(
            args.device_id,
            CertificateTemplate(
                subject=args.subject,
                validity_days=args.days,
                key_size=args.key_size,
            ),
        )

        if args.output_certificate:
            Path(args.output_certificate).write_text(cert.certificate_pem, encoding="utf-8")
        if args.output_private_key:
            Path(args.output_private_key).write_text(cert.private_key_pem, encoding="utf-8")

        print(json.dumps({
            "device_id": cert.device_id,
            "serial_number": cert.serial_number,
            "subject": cert.subject,
            "issued_at": cert.issued_at.isoformat(),
            "expires_at": cert.expires_at.isoformat(),
            "status": cert.status,
            "fingerprint": cert.fingerprint,
            "certificate_file": args.output_certificate,
            "private_key_file": args.output_private_key,
        }, indent=2))
        return

    if args.command == "status":
        record = manager.get_certificate(args.device_id)
        if record is None:
            print(json.dumps({"device_id": args.device_id, "status": "not_found"}, indent=2))
            return

        print(json.dumps({
            "device_id": record.device_id,
            "status": record.status,
            "subject": record.subject,
            "expires_at": record.expires_at.isoformat(),
            "valid": record.is_active(),
        }, indent=2))


if __name__ == "__main__":
    main()
