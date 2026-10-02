"""TLS/SSL posture checks: protocol versions, certificate validity/expiry."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..models import Finding, Severity, Target
from .base import Module

_LEGACY_PROTOCOLS = {
    "SSLv3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None,
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}


class TlsModule(Module):
    name = "tls_check"
    phase = "surface"
    active = True
    intrusive = False

    def run(self, target: Target, ctx) -> list[Finding]:
        findings: list[Finding] = []
        host = target.host
        port = 443

        cert = self._fetch_cert(host, port, ctx.config.timeout)
        if cert is None:
            findings.append(
                Finding(
                    title="No TLS on port 443",
                    severity=Severity.INFO,
                    module=self.name,
                    target=host,
                    category="Transport security",
                    catalog_id="AEG-TLS-000",
                    description="Could not establish a TLS session on 443 (may be HTTP-only).",
                    remediation="Serve the site over HTTPS with a valid certificate.",
                )
            )
            return findings

        # Certificate expiry
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    sev = Severity.HIGH
                    msg = f"Certificate EXPIRED {abs(days)} day(s) ago ({not_after})."
                elif days < 15:
                    sev = Severity.MEDIUM
                    msg = f"Certificate expires in {days} day(s) ({not_after})."
                else:
                    sev = Severity.INFO
                    msg = f"Certificate valid for {days} more day(s)."
                findings.append(
                    Finding(
                        title="TLS certificate expiry",
                        severity=sev,
                        module=self.name,
                        target=host,
                        category="Transport security",
                        catalog_id="AEG-TLS-001",
                        description=msg,
                        evidence=f"notAfter={not_after}",
                        remediation="Automate renewal (e.g. ACME) well before expiry.",
                    )
                )
            except ValueError:
                pass

        # Legacy protocol support
        for proto_name, version in _LEGACY_PROTOCOLS.items():
            if version is None:
                continue
            if self._supports(host, port, version, ctx.config.timeout):
                findings.append(
                    Finding(
                        title=f"Legacy TLS protocol enabled: {proto_name}",
                        severity=Severity.MEDIUM,
                        module=self.name,
                        target=host,
                        category="Transport security",
                        catalog_id="AEG-TLS-002",
                        description=(
                            f"The server negotiated {proto_name}, which is deprecated "
                            "and vulnerable to known attacks."
                        ),
                        remediation="Disable everything below TLS 1.2; prefer TLS 1.3.",
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    )
                )
        return findings

    def _fetch_cert(self, host: str, port: int, timeout: float) -> dict | None:
        # getpeercert() only returns fields when the cert is actually parsed,
        # so read it via a verifying context (with an unverified fallback for
        # self-signed / invalid certs).
        return _cert_via_verifying(host, port, timeout)

    def _supports(self, host: str, port: int, version, timeout: float) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (OSError, ssl.SSLError):
            return False


def _cert_via_verifying(host: str, port: int, timeout: float) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except (OSError, ssl.SSLError):
        # Cert invalid/self-signed: retry without verification to still read dates.
        nover = ssl._create_unverified_context()  # noqa: SLF001
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with nover.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert() or {}
        except (OSError, ssl.SSLError):
            return None
