"""Passive/active reconnaissance: DNS, reverse DNS, common records."""

from __future__ import annotations

import socket

from ..models import Finding, Severity, Target
from .base import Module

try:
    import dns.resolver  # type: ignore

    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False


class ReconModule(Module):
    name = "recon"
    phase = "recon"
    active = True  # DNS queries touch resolvers, not usually the target itself
    intrusive = False

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def run(self, target: Target, ctx) -> list[Finding]:
        findings: list[Finding] = []
        records: dict[str, list[str]] = {}

        if _HAVE_DNS:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = ctx.config.timeout
            for rtype in self.RECORD_TYPES:
                try:
                    answers = resolver.resolve(target.host, rtype)
                    records[rtype] = [r.to_text() for r in answers]
                except Exception:
                    continue
        else:
            ips = target.resolved_ips or []
            if ips:
                records["A"] = ips

        target.metadata["dns"] = records

        # Reverse DNS on resolved IPs (useful to spot shared hosting / cloud)
        ptrs: dict[str, str] = {}
        for ip in target.resolved_ips:
            try:
                ptrs[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                continue
        if ptrs:
            target.metadata["ptr"] = ptrs

        # Informational finding: SPF/DMARC presence (email spoofing posture)
        txt = " ".join(records.get("TXT", []))
        if "v=spf1" not in txt.lower():
            findings.append(
                Finding(
                    title="No SPF record found",
                    severity=Severity.LOW,
                    module=self.name,
                    target=target.host,
                    category="Email security",
                    catalog_id="AEG-EMAIL-001",
                    description=(
                        "No SPF (v=spf1) TXT record was found for the domain. "
                        "This makes sender spoofing easier."
                    ),
                    remediation="Publish an SPF record listing authorized mail senders.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                )
            )

        summary = ", ".join(f"{k}={len(v)}" for k, v in records.items()) or "none"
        findings.append(
            Finding(
                title="DNS reconnaissance",
                severity=Severity.INFO,
                module=self.name,
                target=target.host,
                category="Recon",
                catalog_id="AEG-RECON-001",
                description="Collected DNS records for the target.",
                evidence=f"Records: {summary}. PTR: {ptrs or 'none'}",
                remediation="Informational — review exposed records for over-sharing.",
            )
        )
        return findings
