from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    common_name: str
    organization: str
    environment: str = "production"


@dataclass
class CertificateTemplate:
    subject: str
    validity_days: int = 365
    key_size: int = 2048
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)


@dataclass
class CertificateRecord:
    device_id: str
    serial_number: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    status: str = "issued"
    fingerprint: str = ""

    def is_active(self, current_time: datetime | None = None) -> bool:
        current = current_time or datetime.utcnow()
        return self.status == "issued" and current < self.expires_at
