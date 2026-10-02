"""Technology fingerprinting from HTTP responses (server, framework hints)."""

from __future__ import annotations

import re

from ..models import Finding, Severity, Target
from .base import Module

# Header -> friendly meaning. Presence of these often leaks stack details.
_LEAKY_HEADERS = {
    "server": "Web server / version",
    "x-powered-by": "Application framework / runtime",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "CMS / generator",
    "x-drupal-cache": "Drupal",
    "x-runtime": "Rails runtime timing",
}

_BODY_SIGNATURES = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"Drupal.settings|/sites/default/", re.I), "Drupal"),
    (re.compile(r"content=\"Joomla", re.I), "Joomla"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react-dom", re.I), "React"),
    (re.compile(r"csrf-param.*authenticity_token", re.I), "Ruby on Rails"),
]


class FingerprintModule(Module):
    name = "fingerprint"
    phase = "surface"
    active = True
    intrusive = False

    def run(self, target: Target, ctx) -> list[Finding]:
        findings: list[Finding] = []
        tech: set[str] = set()
        leaks: list[str] = []

        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}"
            resp = ctx.request("GET", url)
            if resp is None:
                continue
            target.urls.append(resp.url)

            for header, meaning in _LEAKY_HEADERS.items():
                value = resp.headers.get(header)
                if value:
                    tech.add(value)
                    leaks.append(f"{header}: {value} ({meaning})")

            body = resp.text[:200_000] if resp.text else ""
            for pattern, label in _BODY_SIGNATURES:
                if pattern.search(body):
                    tech.add(label)
            break  # first scheme that answered is enough

        if tech:
            target.metadata["technologies"] = sorted(tech)
            findings.append(
                Finding(
                    title="Technology fingerprint",
                    severity=Severity.INFO,
                    module=self.name,
                    target=target.host,
                    category="Information gathering",
                    catalog_id="AEG-FP-001",
                    description="Detected technologies from headers and page content.",
                    evidence="; ".join(sorted(tech)),
                    remediation="Informational — feeds later vulnerability mapping.",
                )
            )

        if leaks:
            findings.append(
                Finding(
                    title="Version/stack disclosure in HTTP headers",
                    severity=Severity.LOW,
                    module=self.name,
                    target=target.host,
                    category="Information disclosure",
                    catalog_id="AEG-INFO-001",
                    description=(
                        "Response headers reveal server/framework versions, easing "
                        "targeted attacks against known-vulnerable versions."
                    ),
                    evidence="\n".join(leaks),
                    remediation=(
                        "Suppress or genericize Server/X-Powered-By and similar "
                        "version-bearing headers."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                )
            )
        return findings
