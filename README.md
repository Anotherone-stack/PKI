from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_root_and_health():
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["message"] == "PKI Provisioning API"


def test_register_device_and_issue_certificate():
    device = client.post(
        "/api/devices",
        json={
            "device_id": "device-100",
            "common_name": "device-100.internal",
            "organization": "ExampleOrg",
            "environment": "production",
        },
    )
    assert device.status_code == 200

    cert = client.post(
        "/api/certificates",
        json={
            "device_id": "device-100",
            "subject": "CN=device-100.internal,O=ExampleOrg",
            "validity_days": 30,
            "key_size": 2048,
        },
    )
    assert cert.status_code == 200
    body = cert.json()
    assert body["device_id"] == "device-100"
    assert body["certificate"].startswith("-----BEGIN CERTIFICATE-----")


def test_certificate_validity_and_listing():
    device = client.post(
        "/api/devices",
        json={
            "device_id": "device-101",
            "common_name": "device-101.internal",
            "organization": "ExampleOrg",
        },
    )
    assert device.status_code == 200

    client.post(
        "/api/certificates",
        json={
            "device_id": "device-101",
            "subject": "CN=device-101.internal,O=ExampleOrg",
            "validity_days": 365,
        },
    )

    valid = client.get("/api/certificates/device-101/validity")
    assert valid.status_code == 200
    assert valid.json()["valid"] is True

    listed = client.get("/api/certificates")
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1


def test_status_and_audit_endpoints():
    status = client.get("/api/status")
    assert status.status_code == 200
    assert status.json()["service"] == "pki-provisioning"
    assert status.json()["store"] == "file-backed"

    audit = client.get("/api/audit")
    assert audit.status_code == 200
    assert audit.json()["count"] >= 0


def test_revocation_and_renewal_api_flow():
    client.post(
        "/api/devices",
        json={
            "device_id": "device-102",
            "common_name": "device-102.internal",
            "organization": "ExampleOrg",
        },
    )

    issued = client.post(
        "/api/certificates",
        json={
            "device_id": "device-102",
            "subject": "CN=device-102.internal,O=ExampleOrg",
            "validity_days": 30,
        },
    )
    assert issued.status_code == 200

    revoked = client.post(
        "/api/certificates/device-102/revoke",
        json={"reason": "rotation"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    renewed = client.post(
        "/api/certificates/device-102/renew",
        json={
            "subject": "CN=device-102.internal,O=ExampleOrg",
            "validity_days": 90,
            "key_size": 2048,
        },
    )
    assert renewed.status_code == 200
    assert renewed.json()["status"] == "issued"
