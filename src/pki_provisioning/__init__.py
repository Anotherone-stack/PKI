from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .models import CertificateTemplate, DeviceIdentity


class CertificateFactory:
    @staticmethod
    def _parse_name(subject: str) -> x509.Name:
        parts = []
        for item in subject.split(","):
            segment = item.strip()
            if not segment:
                continue
            if "=" not in segment:
                continue
            key, value = [part.strip() for part in segment.split("=", 1)]
            oid_map = {
                "CN": NameOID.COMMON_NAME,
                "O": NameOID.ORGANIZATION_NAME,
                "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
                "C": NameOID.COUNTRY_NAME,
                "ST": NameOID.STATE_OR_PROVINCE_NAME,
                "L": NameOID.LOCALITY_NAME,
                "emailAddress": NameOID.EMAIL_ADDRESS,
            }
            if key in oid_map:
                parts.append(x509.NameAttribute(oid_map[key], value))

        if not parts:
            return x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject),
            ])

        return x509.Name(parts)

    @staticmethod
    def _build_san_extension(template: CertificateTemplate) -> x509.SubjectAlternativeName | None:
        names = []
        for dns_name in template.san_dns:
            names.append(x509.DNSName(dns_name))
        for ip_value in template.san_ip:
            names.append(x509.IPAddress(ipaddress.ip_address(ip_value)))

        if not names:
            return None

        return x509.SubjectAlternativeName(names)

    @staticmethod
    def generate_certificate(device: DeviceIdentity, template: CertificateTemplate) -> dict:
        key = rsa.generate_private_key(public_exponent=65537, key_size=template.key_size)
        subject = CertificateFactory._parse_name(template.subject)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=template.validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)
        )

        san_extension = CertificateFactory._build_san_extension(template)
        if san_extension is not None:
            cert = cert.add_extension(san_extension, critical=False)

        certificate = cert.sign(key, hashes.SHA256())

        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        return {
            "device_id": device.device_id,
            "subject": template.subject,
            "serial_number": format(certificate.serial_number, "x"),
            "private_key_pem": private_key_pem,
            "certificate_pem": certificate_pem,
        }
