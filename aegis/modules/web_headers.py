"""HTTP security-header hygiene, cookie flags, and a few safe info-leak checks."""

from __future__ import annotations

from ..models import Confidence, Finding, Severity, Target
from .base import Module

# header -> (title, severity, remediation)
_EXPECTED = {
    "strict-transport-security": (
        "Missing HSTS header",
        Severity.MEDIUM,
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy",
        Severity.MEDIUM,
        "Define a restrictive CSP to mitigate XSS and data injection.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        Severity.LOW,
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options / frame-ancestors",
        Severity.LOW,
        "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        Severity.INFO,
        "Add a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    ),
}

# Paths that commonly leak information if present. All GETs, non-destructive.
_PROBE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/robots.txt",
    "/.well-known/security.txt",
    "/server-status",
    "/actuator/health",
    "/phpinfo.php",
]


class WebHeadersModule(Module):
    name = "web_headers"
    phase = "web"
    active = True
    intrusive = False

    def run(self, target: Target, ctx) -> list[Finding]:
        findings: list[Finding] = []
        base = None
        resp = None
        for scheme in ("https", "http"):
            resp = ctx.request("GET", f"{scheme}://{target.host}")
            if resp is not None:
                base = f"{scheme}://{target.host}"
                break
        if resp is None or base is None:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Missing security headers
        for header, (title, sev, fix) in _EXPECTED.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title=title,
                        severity=sev,
                        module=self.name,
                        target=target.host,
                        category="Security misconfiguration",
                        catalog_id="AEG-HDR-001",
                        description=f"Response is missing the '{header}' header.",
                        evidence=f"{base} did not return '{header}'.",
                        remediation=fix,
                        references=[
                            "https://owasp.org/www-project-secure-headers/"
                        ],
                    )
                )

        # 2. Cookie flags
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly")
            if issues:
                findings.append(
                    Finding(
                        title=f"Insecure cookie flags: {cookie.name}",
                        severity=Severity.LOW,
                        module=self.name,
                        target=target.host,
                        category="Security misconfiguration",
                        catalog_id="AEG-HDR-002",
                        description=f"Cookie '{cookie.name}' has: {', '.join(issues)}.",
                        remediation="Set Secure, HttpOnly and SameSite on session cookies.",
                    )
                )

        # 3. Sensitive path exposure (safe GET probes)
        for path in _PROBE_PATHS:
            probe = ctx.request("GET", base + path)
            if probe is None or probe.status_code >= 400:
                continue
            snippet = (probe.text or "")[:120].replace("\n", " ")
            sev = Severity.HIGH if path in ("/.git/HEAD", "/.env") else Severity.MEDIUM
            if path in ("/robots.txt", "/.well-known/security.txt"):
                sev = Severity.INFO
            findings.append(
                Finding(
                    title=f"Reachable sensitive path: {path}",
                    severity=sev,
                    module=self.name,
                    target=target.host,
                    category="Information disclosure",
                    catalog_id="AEG-INFO-002",
                    confidence=Confidence.FIRM,
                    description=f"{base + path} returned HTTP {probe.status_code}.",
                    evidence=f"First bytes: {snippet!r}",
                    remediation="Remove or restrict access to this path.",
                )
            )
        return findings
