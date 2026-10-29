from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

from .certificate_factory import CertificateFactory
from .models import CertificateRecord, CertificateTemplate, DeviceIdentity
from .store import FileStore


class CertificateManager:
    def __init__(self, storage_path: str | Path | None = None) -> None:
        self._storage_path = storage_path or Path("pki_store.json")
        self._store = FileStore(self._storage_path)
        self._devices: Dict[str, DeviceIdentity] = {}
        self._certificates: Dict[str, CertificateRecord] = {}
        self._audit_log: List[dict] = []
        self._load_state()

    def _append_audit(self, event: str, **details: object) -> None:
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **details,
        })

    def _persist(self) -> None:
        state = {
            "devices": {
                device_id: {
                    "device_id": device.device_id,
                    "common_name": device.common_name,
                    "organization": device.organization,
                    "environment": device.environment,
                }
                for device_id, device in self._devices.items()
            },
            "certificates": {
                device_id: {
                    "device_id": cert.device_id,
                    "serial_number": cert.serial_number,
                    "subject": cert.subject,
                    "issued_at": cert.issued_at.isoformat(),
                    "expires_at": cert.expires_at.isoformat(),
                    "status": cert.status,
                    "fingerprint": cert.fingerprint,
                    "private_key_pem": cert.private_key_pem,
                    "certificate_pem": cert.certificate_pem,
                    "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
                    "revoked_reason": cert.revoked_reason,
                }
                for device_id, cert in self._certificates.items()
            },
            "audit_log": self._audit_log,
        }
        self._store.save(state)

    def _load_state(self) -> None:
        state = self._store.load()
        devices = state.get("devices", {})
        certificates = state.get("certificates", {})
        self._audit_log = list(state.get("audit_log", []))

        self._devices = {
            device_id: DeviceIdentity(
                device_id=payload["device_id"],
                common_name=payload["common_name"],
                organization=payload["organization"],
                environment=payload.get("environment", "production"),
            )
            for device_id, payload in devices.items()
        }

        self._certificates = {
            device_id: CertificateRecord(
                device_id=payload["device_id"],
                serial_number=payload["serial_number"],
                subject=payload["subject"],
                issued_at=datetime.fromisoformat(payload["issued_at"]),
                expires_at=datetime.fromisoformat(payload["expires_at"]),
                status=payload.get("status", "issued"),
                fingerprint=payload.get("fingerprint", ""),
                private_key_pem=payload.get("private_key_pem", ""),
                certificate_pem=payload.get("certificate_pem", ""),
                revoked_at=datetime.fromisoformat(payload["revoked_at"]) if payload.get("revoked_at") else None,
                revoked_reason=payload.get("revoked_reason", ""),
            )
            for device_id, payload in certificates.items()
        }

    def register_device(self, identity: DeviceIdentity) -> DeviceIdentity:
        self._devices[identity.device_id] = identity
        self._append_audit("device_registered", device_id=identity.device_id, organization=identity.organization)
        self._persist()
        return identity

    def get_device(self, device_id: str) -> DeviceIdentity | None:
        return self._devices.get(device_id)

    def create_certificate(
        self,
        device_id: str,
        template: CertificateTemplate,
    ) -> CertificateRecord:
        if device_id not in self._devices:
            raise ValueError(f"Unknown device: {device_id}")

        device = self._devices[device_id]
        certificate = CertificateFactory.generate_certificate(device, template)

        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(days=template.validity_days)
        serial_number = certificate["serial_number"]
        fingerprint = hashlib.sha256(certificate["certificate_pem"].encode("utf-8")).hexdigest()

        record = CertificateRecord(
            device_id=device_id,
            serial_number=serial_number,
            subject=certificate["subject"],
            issued_at=issued_at,
            expires_at=expires_at,
            status="issued",
            fingerprint=fingerprint,
            private_key_pem=certificate["private_key_pem"],
            certificate_pem=certificate["certificate_pem"],
        )
        self._certificates[device_id] = record
        self._append_audit("certificate_issued", device_id=device_id, serial_number=serial_number, subject=record.subject)
        self._persist()
        return record

    def get_certificate(self, device_id: str) -> CertificateRecord | None:
        return self._certificates.get(device_id)

    def revoke_certificate(self, device_id: str, reason: str = "unspecified") -> CertificateRecord:
        record = self._certificates.get(device_id)
        if record is None:
            raise ValueError(f"No certificate found for device: {device_id}")

        record.status = "revoked"
        record.revoked_at = datetime.now(timezone.utc)
        record.revoked_reason = reason
        self._append_audit("certificate_revoked", device_id=device_id, reason=reason, serial_number=record.serial_number)
        self._persist()
        return record

    def renew_certificate(
        self,
        device_id: str,
        template: CertificateTemplate | None = None,
    ) -> CertificateRecord:
        record = self._certificates.get(device_id)
        if record is None:
            raise ValueError(f"No certificate found for device: {device_id}")

        if template is None:
            template = CertificateTemplate(
                subject=record.subject,
                validity_days=max(1, (record.expires_at - record.issued_at).days or 1),
                key_size=2048,
            )

        old_serial = record.serial_number
        record.status = "revoked"
        record.revoked_at = datetime.now(timezone.utc)
        record.revoked_reason = "renewed"

        new_record = self.create_certificate(device_id, template)
        self._append_audit("certificate_renewed", device_id=device_id, old_serial_number=old_serial, new_serial_number=new_record.serial_number)
        self._persist()
        return new_record

    def get_audit_log(self) -> List[dict]:
        return list(self._audit_log)

    def is_certificate_valid(self, device_id: str, current_time: datetime | None = None) -> bool:
        record = self._certificates.get(device_id)
        if record is None:
            return False
        return record.is_active(current_time)

    def list_certificates(self) -> List[CertificateRecord]:
        return list(self._certificates.values())
