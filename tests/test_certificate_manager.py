from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from pki_provisioning.certificate_manager import CertificateManager
from pki_provisioning.models import CertificateTemplate, DeviceIdentity

manager = CertificateManager(storage_path="pki_store.json")


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


class RevokeCertificateRequest(BaseModel):
    reason: str = Field(default="unspecified")


class RenewCertificateRequest(BaseModel):
    subject: str | None = None
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
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revoked_reason": cert.revoked_reason,
    }


@app.get("/certificates/{device_id}")
def get_certificate(device_id: str) -> dict:
    cert = manager.get_certificate(device_id)
    if cert is None:
        raise HTTPException(status_code=404, detail=f"No certificate found for device: {device_id}")

    return {
        "device_id": cert.device_id,
        "serial_number": cert.serial_number,
        "subject": cert.subject,
        "issued_at": cert.issued_at.isoformat(),
        "expires_at": cert.expires_at.isoformat(),
        "status": cert.status,
        "valid": cert.is_active(),
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revoked_reason": cert.revoked_reason,
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
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revoked_reason": cert.revoked_reason,
    }


@app.post("/certificates/{device_id}/revoke")
def revoke_certificate(device_id: str, payload: RevokeCertificateRequest) -> dict:
    cert = manager.revoke_certificate(device_id, reason=payload.reason)
    return {
        "device_id": cert.device_id,
        "serial_number": cert.serial_number,
        "status": cert.status,
        "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
        "revoked_reason": cert.revoked_reason,
    }


@app.post("/certificates/{device_id}/renew")
def renew_certificate(device_id: str, payload: RenewCertificateRequest) -> dict:
    if payload.subject is None:
        current = manager.get_certificate(device_id)
        if current is None:
            raise HTTPException(status_code=404, detail=f"No certificate found for device: {device_id}")
        subject = current.subject
    else:
        subject = payload.subject

    cert = manager.renew_certificate(
        device_id,
        CertificateTemplate(
            subject=subject,
            validity_days=payload.validity_days,
            key_size=payload.key_size,
        ),
    )
    return {
        "device_id": cert.device_id,
        "serial_number": cert.serial_number,
        "subject": cert.subject,
        "issued_at": cert.issued_at.isoformat(),
        "expires_at": cert.expires_at.isoformat(),
        "status": cert.status,
        "valid": cert.is_active(),
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
                "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
                "revoked_reason": cert.revoked_reason,
            }
            for cert in certs
        ],
    }


@app.get("/audit")
def audit_log() -> dict:
    return {"count": len(manager.get_audit_log()), "entries": manager.get_audit_log()}


@app.get("/status")
def status() -> dict:
    certs = manager.list_certificates()
    valid = sum(1 for cert in certs if cert.is_active())
    revoked = sum(1 for cert in certs if cert.status == "revoked")
    expired = sum(1 for cert in certs if cert.status == "issued" and cert.expires_at <= cert.issued_at)
    return {
        "service": "pki-provisioning",
        "devices_registered": len(manager._devices),
        "certificates_issued": len(certs),
        "valid_certificates": valid,
        "revoked_certificates": revoked,
        "expired_certificates": expired,
        "store": "file-backed",
        "audit_entries": len(manager.get_audit_log()),
    }
