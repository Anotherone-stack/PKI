from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from pki_provisioning.certificate_manager import CertificateManager
from pki_provisioning.models import CertificateTemplate, DeviceIdentity

manager = CertificateManager()


class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    common_name: str = Field(..., min_length=1)
    organization: str = Field(..., min_length=1)
    environment: str = Field(default="production")


class IssueCertificateRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)
    validity_days: int = Field(default=365, gt=0)
    key_size: int = Field(default=2048, ge=2048, le=4096)


app = FastAPI(title="PKI Provisioning API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pki-provisioning"}


@app.post("/devices")
def register_device(payload: DeviceRegisterRequest) -> dict:
    device = manager.register_device(
        DeviceIdentity(
            device_id=payload.device_id,
            common_name=payload.common_name,
            organization=payload.organization,
            environment=payload.environment,
        )
    )
    return {"device": device.__dict__}


@app.post("/certificates")
def issue_certificate(payload: IssueCertificateRequest) -> dict:
    if payload.device_id not in manager._devices:
        raise HTTPException(status_code=404, detail=f"Unknown device: {payload.device_id}")

    cert = manager.create_certificate(
        payload.device_id,
        CertificateTemplate(
            subject=payload.subject,
            validity_days=payload.validity_days,
            key_size=payload.key_size,
        ),
    )

    return {
        "device_id": cert.device_id,
        "subject": cert.subject,
        "serial_number": cert.serial_number,
        "issued_at": cert.issued_at.isoformat(),
        "expires_at": cert.expires_at.isoformat(),
        "status": cert.status,
        "fingerprint": cert.fingerprint,
        "certificate": cert.certificate_pem,
        "private_key": cert.private_key_pem,
    }


@app.get("/certificates/{device_id}/validity")
def check_validity(device_id: str) -> dict:
    cert = manager.get_certificate(device_id)
    if cert is None:
        raise HTTPException(status_code=404, detail=f"No certificate found for device: {device_id}")

    return {
        "device_id": device_id,
        "valid": cert.is_active(),
        "status": cert.status,
        "expires_at": cert.expires_at.isoformat(),
    }


@app.get("/certificates")
def list_certificates() -> dict:
    certs = manager.list_certificates()
    return {
        "count": len(certs),
        "certificates": [
            {
                "device_id": cert.device_id,
                "serial_number": cert.serial_number,
                "subject": cert.subject,
                "issued_at": cert.issued_at.isoformat(),
                "expires_at": cert.expires_at.isoformat(),
                "status": cert.status,
                "valid": cert.is_active(),
            }
            for cert in certs
        ],
    }


@app.get("/status")
def status() -> dict:
    return {
        "service": "pki-provisioning",
        "devices_registered": len(manager._devices),
        "certificates_issued": len(manager._certificates),
        "store": "in-memory",
    }
