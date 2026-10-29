from datetime import timedelta

from cryptography import x509

from pki_provisioning.certificate_manager import CertificateManager
from pki_provisioning.models import CertificateTemplate, DeviceIdentity


def test_register_and_issue_certificate():
    manager = CertificateManager(storage_path=".tmp-test-store.json")

    manager.register_device(
        DeviceIdentity(
            device_id="device-001",
            common_name="device-001.internal",
            organization="ExampleOrg",
            environment="production",
        )
    )

    cert = manager.create_certificate(
        "device-001",
        CertificateTemplate(subject="CN=device-001.internal,O=ExampleOrg", validity_days=90),
    )

    assert cert.device_id == "device-001"
    assert cert.status == "issued"
    assert cert.expires_at > cert.issued_at
    assert cert.private_key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert manager.is_certificate_valid("device-001") is True

    loaded = x509.load_pem_x509_certificate(cert.certificate_pem.encode("utf-8"))
    assert loaded.subject.rfc4514_string() == "CN=device-001.internal,O=ExampleOrg"


def test_certificate_expiry_check():
    manager = CertificateManager(storage_path=".tmp-test-store.json")
    manager.register_device(
        DeviceIdentity(
            device_id="device-002",
            common_name="device-002.internal",
            organization="ExampleOrg",
        )
    )

    cert = manager.create_certificate(
        "device-002",
        CertificateTemplate(subject="CN=device-002.internal,O=ExampleOrg", validity_days=1),
    )

    expired_time = cert.expires_at + timedelta(days=1)
    assert manager.is_certificate_valid("device-002", current_time=expired_time) is False


def test_unknown_device_raises_error():
    manager = CertificateManager(storage_path=".tmp-test-store.json")

    try:
        manager.create_certificate("missing-device", CertificateTemplate(subject="CN=missing"))
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_file_persistence_across_instances(tmp_path):
    store_path = tmp_path / "pki_store.json"

    first = CertificateManager(storage_path=store_path)
    first.register_device(
        DeviceIdentity(device_id="device-003", common_name="device-003.internal", organization="ExampleOrg")
    )
    first.create_certificate("device-003", CertificateTemplate(subject="CN=device-003.internal,O=ExampleOrg", validity_days=7))

    second = CertificateManager(storage_path=store_path)
    assert second.get_device("device-003") is not None
    assert second.get_certificate("device-003") is not None
    assert second.is_certificate_valid("device-003") is True


def test_revocation_and_renewal_flow():
    manager = CertificateManager(storage_path=".tmp-test-store.json")
    manager.register_device(
        DeviceIdentity(device_id="device-004", common_name="device-004.internal", organization="ExampleOrg")
    )
    original = manager.create_certificate(
        "device-004",
        CertificateTemplate(subject="CN=device-004.internal,O=ExampleOrg", validity_days=30),
    )

    revoked = manager.revoke_certificate("device-004", reason="rotation")
    assert revoked.status == "revoked"
    assert revoked.revoked_reason == "rotation"

    renewed = manager.renew_certificate(
        "device-004",
        CertificateTemplate(subject="CN=device-004.internal,O=ExampleOrg", validity_days=90),
    )
    assert renewed.status == "issued"
    assert renewed.serial_number != original.serial_number
    assert len(manager.get_audit_log()) >= 4
