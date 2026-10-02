# Aegis Assessment Methodology

Aegis implements a black-box (no source access) external assessment aligned with
recognized standards:

- **OWASP WSTG** (Web Security Testing Guide)
- **OWASP Top 10 (2021)** and **OWASP API Security Top 10 (2023)**
- **PTES** (Penetration Testing Execution Standard)
- **NIST SP 800-115** (Technical Guide to Information Security Testing)

The goal is coverage that is **repeatable, auditable and non-destructive**. Where
a check cannot be safely automated as an external probe, it is still listed in
the [catalog](vulnerabilities.yaml) so a licensed operator performs it manually
under the signed scope — nothing is silently skipped.

## Phases

### 0. Pre-engagement (out of band)
- Signed authorization + rules of engagement (see `config/authorization.yaml`).
- Scope defined and **hashed** into the authorization (tamper-evidence).
- Emergency contacts and testing window agreed.

### 1. Reconnaissance (`recon`)
Passive/active intelligence: DNS records, reverse DNS, mail posture (SPF),
provider identification. Subdomain and OSINT discovery are operator-driven.

### 2. Attack-surface mapping (`portscan`, `tls_check`, `fingerprint`)
Enumerate reachable services and their versions; assess TLS posture; fingerprint
the technology stack. This is what an attacker maps first.

### 3. Web posture (`web_headers`)
Security-header hygiene, cookie flags, and safe probes for sensitive exposed
paths (`.git`, `.env`, actuator/status endpoints).

### 4. Vulnerability detection (`nuclei`, manual)
Template-based detection of known issues (opt-in, intrusive). Injection, access
control, SSRF, business-logic and authentication testing are performed manually
by the operator — these require judgment and safe, targeted probing rather than
blind automation.

### 5. Correlation, scoring & reporting
Findings are deduplicated, severity-scored, mapped to catalog entries, and
written to `report.html` / `report.md` / `findings.json`, plus a full
`evidence.log` request trail.

## Safety rules (enforced, not advisory)
1. Every target is gated by the signed scope — no override flag exists.
2. All traffic is rate-limited to the scope's `max_rps`.
3. Intrusive modules require **both** scope `allow_intrusive: true` **and** the
   `--enable-intrusive` run flag.
4. No destructive actions, DoS, data modification, or persistence — ever.
5. Every request is logged for the client's audit trail.

## Severity model
Severities follow a CVSS-informed qualitative scale
(`info < low < medium < high < critical`). Each finding records confidence
(`tentative | firm | confirmed`) so the reader can weigh automated signals
against operator-confirmed issues.

## Reporting deliverables
- **Executive summary** — counts by severity, overall posture.
- **Findings** — description, evidence, remediation, references, catalog id.
- **Evidence log** — every request/response for reproducibility.
- **Retest** — re-run `aegis run` after fixes to confirm closure.
