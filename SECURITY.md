
# 🔐 Security Policy

## Security at PKI Wiki

Security is fundamental to everything we build.

The PKI Wiki is dedicated to promoting secure development practices, trusted digital identities, cryptographic integrity, and the protection of connected devices throughout their lifecycle.

We take security vulnerabilities seriously and encourage responsible disclosure from security researchers, developers, partners, and members of the community.

Our objective is to identify, assess, and address security risks while maintaining the confidentiality, integrity, and availability of our systems and information.

---

## 1. Supported Versions

We recommend using actively maintained and approved versions of our software and documentation.

Security updates and vulnerability fixes are prioritized for supported releases.

| Version | Support Status | Security Updates |
|:---|:---:|:---:|
| 5.1.x | ✅ Supported | Active |
| 5.0.x | ⚠️ Limited Support | As applicable |
| 4.0.x | ✅ Supported | Active |
| < 4.0 | ❌ Unsupported | Not provided |

> **Note:** Update this table to reflect your organization's actual release and maintenance policy.

---

## 2. Reporting a Vulnerability

We appreciate the work of security researchers and community members who help identify potential vulnerabilities.

If you discover a security issue, please report it responsibly so that our team can investigate and address it.

### What Should Be Reported?

Examples of security concerns include:

- **Cryptographic Security:** Weak algorithms, compromised keys, or improper cryptographic implementation.
- **Certificate Management:** Certificate misuse, unauthorized issuance, or validation weaknesses.
- **Device Identity:** Identity spoofing, impersonation, or unauthorized device enrollment.
- **Secure Provisioning:** Vulnerabilities in key injection, manufacturing, or device onboarding.
- **Authentication & Authorization:** Unauthorized access or privilege escalation.
- **Infrastructure Security:** Exposed credentials, insecure APIs, or configuration weaknesses.
- **Data Protection:** Unauthorized disclosure or manipulation of sensitive information.

### How to Report

Please submit vulnerability reports through the organization's designated security reporting channel.

**Security Contact:** [security@your-company.com]

**Alternative Reporting Method:** [Insert approved security reporting URL]

Please include the following information whenever possible:

1. A clear description of the vulnerability.
2. The affected product, component, or version.
3. Steps to reproduce the issue.
4. Potential security impact and severity.
5. Supporting evidence or proof of concept.
6. Suggested mitigation, if available.

> Never include private keys, passwords, production credentials, or other sensitive secrets in a vulnerability report.

---

## 3. Responsible Disclosure Process

We follow a coordinated vulnerability disclosure approach designed to protect users and systems while security issues are investigated.

| Stage | Activity |
|:---|:---|
| 01 — Submission | Vulnerability report received. |
| 02 — Acknowledgment | Report reviewed and receipt confirmed. |
| 03 — Assessment | Technical investigation and severity evaluation. |
| 04 — Remediation | Mitigation, security fixes, or corrective actions developed. |
| 05 — Resolution | Fix validated and deployed where applicable. |
| 06 — Closure | Reporter receives an appropriate resolution update. |

### Expected Response Times

The following are proposed service targets and should be confirmed by the organization before publication.

| Activity | Target |
|:---|:---|
| Initial acknowledgment | Within 3 business days |
| Initial assessment | Within 5 business days |
| Status communication | At least every 10 business days |
| Resolution | Based on severity and remediation complexity |

---

## 4. Vulnerability Assessment & Severity

Reported vulnerabilities are evaluated according to their potential impact, exploitability, affected components, and risk to users and connected devices.

| Severity | Description | Response Priority |
|:---|:---|:---|
| 🔴 Critical | Direct compromise of trust infrastructure, private keys, or critical security controls. | Immediate |
| 🟠 High | Significant security impact, unauthorized access, or identity compromise. | Urgent |
| 🟡 Medium | Limited exploitation potential or security control weakness. | Planned |
| 🟢 Low | Minor security concerns with limited impact. | As scheduled |

Severity classifications may be informed by CVSS and organizational risk assessment procedures.

---

## 5. Scope of Security

Security reviews should consider the complete device identity lifecycle, including:

- Secure microcontroller architecture.
- Hardware Root of Trust.
- Cryptographic key generation and storage.
- Public Key Infrastructure (PKI).
- Certificate Authority (CA) operations.
- Device identity generation.
- Secure manufacturing and provisioning.
- Certificate enrollment and authentication.
- Certificate renewal and revocation.
- Device lifecycle management.
- Secure communication and infrastructure.

---

## 6. Responsible Research Guidelines

We encourage ethical security research and coordinated vulnerability disclosure.

Researchers are requested to:

- Avoid accessing or modifying data belonging to others.
- Avoid disrupting production systems or services.
- Avoid destructive testing and denial-of-service activities.
- Never extract, disclose, or misuse private cryptographic keys.
- Protect confidential information discovered during testing.
- Allow reasonable time for investigation and remediation before public disclosure.
- Report findings through the designated security channel.

---

## 7. Communication & Resolution

After receiving a vulnerability report, the security team will evaluate the findings and determine the appropriate response.

Possible outcomes include:

**Accepted:** The issue is confirmed and prioritized for remediation.

**Under Investigation:** Additional technical analysis or supporting information is required.

**Declined:** The issue is not reproducible, falls outside the supported scope, or does not represent a security vulnerability.

Where appropriate, the reporter will receive an explanation of the decision and available remediation information.

---

## 8. Security Commitment

We believe that digital trust must be established, maintained, and continuously validated.

Our commitment is to:

- Protect the integrity of digital identities.
- Strengthen cryptographic security practices.
- Promote secure device provisioning.
- Protect sensitive credentials and cryptographic material.
- Encourage responsible vulnerability disclosure.
- Continuously improve security throughout the device lifecycle.

---

<div align="center">

### TRUST IS BUILT IN. SECURITY IS CONTINUOUS.

**PKI Wiki | Security & Trust Framework**

© 2026 Your Company. All rights reserved.

</div>
