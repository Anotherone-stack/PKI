from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from .models import CertificateRecord, CertificateTemplate, DeviceIdentity


class CertificateManager:
    def __init__(self) -> None:
        self._devices: Dict[str, DeviceIdentity] = {}
        self._certificates: Dict[str, CertificateRecord] = {}

    def register_device(self, identity: DeviceIdentity) -> DeviceIdentity:
        self._devices[identity.device_id] = identity
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

        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(days=template.validity_days)
        serial_number = f"{device_id}-{int(issued_at.timestamp())}"
        fingerprint = hashlib.sha256(
            f"{device_id}:{serial_number}:{template.subject}".encode("utf-8")
        ).hexdigest()

        record = CertificateRecord(
            device_id=device_id,
            serial_number=serial_number,
            subject=template.subject,
            issued_at=issued_at,
            expires_at=expires_at,
            status="issued",
            fingerprint=fingerprint,
        )
        self._certificates[device_id] = record
        return record

    def get_certificate(self, device_id: str) -> CertificateRecord | None:
        return self._certificates.get(device_id)

    def is_certificate_valid(self, device_id: str, current_time: datetime | None = None) -> bool:
        record = self._certificates.get(device_id)
        if record is None:
            return False
        return record.is_active(current_time)

    def list_certificates(self) -> List[CertificateRecord]:
        return list(self._certificates.values())
