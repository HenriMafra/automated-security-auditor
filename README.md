# Automated Security Auditor: External Attack Surface Reconnaissance and OWASP Compliance Assessment

**Author:** Henri Mafra  
**License:** MIT License  
**Domain:** Information Security, Attack Surface Management, Vulnerability Assessment  

---

## 1. Overview

Automated Security Auditor is a modular Python framework engineered for automated external security posture evaluation, network surface mapping, and compliance auditing against authorized internet-facing endpoints. The tool audits HTTP security headers against **OWASP recommendations**, inspects **X.509 SSL/TLS certificate chains**, and validates DNS zone records to mitigate email spoofing and domain takeover risks.

---

## 2. Legal Notice and Authorized Testing Policy

**RESTRICTED USE AUTHORIZATION:** This software is designed exclusively for testing systems that are explicitly owned by the operator or for which unambiguous, written authorization has been granted. Unauthorized target assessment violates applicable national and international cybercrime statutes. The author disclaims all liability for unauthorized deployment.

---

## 3. Auditing Methodology and Subsystems

### 3.1. OWASP Security Header Inspection
Evaluates mandatory defense-in-depth headers:
- `Strict-Transport-Security` (HSTS): Minimum max-age verification ($T \ge 31536000$) and `includeSubDomains` enforcement.
- `Content-Security-Policy` (CSP): Detection of unsafe directives (`'unsafe-inline'`, `'unsafe-eval'`, wildcard origins `*`).
- `X-Frame-Options`: Anti-clickjacking verification (`DENY` or `SAMEORIGIN`).
- `X-Content-Type-Options`: Prevention of MIME-type sniffing (`nosniff`).

### 3.2. Cryptographic SSL/TLS Assessment
- Validates certificate expiration deadlines with proactive 30-day alerts.
- Inspects supported protocol versions, flagging obsolete protocols (SSL 3.0, TLS 1.0, TLS 1.1).
- Validates root and intermediate Certificate Authority (CA) signature chains.

### 3.3. DNS Hygiene and Spoofing Prevention
- Resolves and verifies SPF (`v=spf1`) syntax and strict terminal mechanisms (`-all` vs. `~all`).
- Confirms presence of DMARC (`_dmarc.domain`) policies with enforcement modes (`reject`, `quarantine`).

---

## 4. Setup and Execution

```bash
# 1. Clone repository
git clone https://github.com/HenriMafra/automated-security-auditor.git
cd automated-security-auditor

# 2. Setup virtual environment
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Execute audit on authorized target
python -m aegis.cli scan --target example.com --output report.json
```

---

## 5. References

- Open Web Application Security Project (OWASP). (2023). *OWASP Secure Headers Project*.
- Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. RFC 8446.

---

## 6. License

Licensed under the MIT License. Copyright (c) Henri Mafra.
