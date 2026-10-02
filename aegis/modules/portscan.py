"""Service discovery.

Uses ``nmap`` when available (service/version detection); otherwise falls back
to a lightweight native TCP connect scan over the configured/default ports.
Both honor the scope's port allow-list and the rate limiter.
"""

from __future__ import annotations

import socket
import subprocess
import xml.etree.ElementTree as ET

from .. import utils
from ..config import DEFAULT_PORTS
from ..models import Finding, Service, Severity, Target
from .base import Module

# Ports that are noteworthy if exposed to the internet.
_SENSITIVE = {
    23: ("Telnet", Severity.HIGH),
    3389: ("RDP", Severity.MEDIUM),
    3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM),
    6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    2375: ("Docker API", Severity.CRITICAL),
    445: ("SMB", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH),
}


class PortScanModule(Module):
    name = "portscan"
    phase = "surface"
    active = True
    intrusive = False

    def _ports(self, ctx) -> list[int]:
        scope_ports = ctx.guard.scope.allowed_ports
        if scope_ports:
            return scope_ports
        if ctx.config.ports:
            return ctx.config.ports
        return DEFAULT_PORTS

    def run(self, target: Target, ctx) -> list[Finding]:
        ports = self._ports(ctx)
        if utils.have_tool("nmap"):
            services = self._nmap(target.host, ports, ctx)
        else:
            utils.warn("    nmap not found — using native TCP connect scan")
            services = self._native(target.host, ports, ctx)

        target.services = services
        findings: list[Finding] = []

        open_desc = ", ".join(
            f"{s.port}/{s.service or 'tcp'}" for s in services
        ) or "none"
        findings.append(
            Finding(
                title=f"{len(services)} open port(s) discovered",
                severity=Severity.INFO,
                module=self.name,
                target=target.host,
                category="Attack surface",
                catalog_id="AEG-NET-001",
                description="Reachable TCP services on the target.",
                evidence=f"Open: {open_desc}",
                remediation="Ensure only necessary services are internet-exposed.",
            )
        )

        for s in services:
            if s.port in _SENSITIVE:
                label, sev = _SENSITIVE[s.port]
                findings.append(
                    Finding(
                        title=f"Sensitive service exposed: {label} (port {s.port})",
                        severity=sev,
                        module=self.name,
                        target=target.host,
                        category="Attack surface",
                        catalog_id="AEG-NET-002",
                        description=(
                            f"{label} is reachable on port {s.port}. Administrative "
                            "and database services should not be exposed to untrusted "
                            "networks."
                        ),
                        evidence=f"{s.port}/tcp open {s.product} {s.version}".strip(),
                        remediation=(
                            "Restrict access with a firewall/VPN/allow-list and "
                            "enforce strong authentication."
                        ),
                    )
                )
        return findings

    # ---- backends -----------------------------------------------------
    def _native(self, host: str, ports: list[int], ctx) -> list[Service]:
        services: list[Service] = []
        for port in ports:
            ctx.rate.acquire()
            try:
                with socket.create_connection((host, port), timeout=min(ctx.config.timeout, 3)):
                    services.append(Service(port=port, service=_guess(port)))
            except OSError:
                continue
        return services

    def _nmap(self, host: str, ports: list[int], ctx) -> list[Service]:
        port_arg = ",".join(str(p) for p in ports)
        cmd = [
            "nmap", "-Pn", "-sT", "-sV", "--version-light",
            "-p", port_arg, "-oX", "-", host,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=max(60, ctx.config.timeout * 10)
            )
        except (subprocess.SubprocessError, OSError) as exc:
            utils.warn(f"    nmap failed ({exc}); falling back to native scan")
            return self._native(host, ports, ctx)
        return _parse_nmap_xml(proc.stdout)


def _guess(port: int) -> str:
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
        8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
    }
    return common.get(port, "")


def _parse_nmap_xml(xml: str) -> list[Service]:
    services: list[Service] = []
    if not xml.strip():
        return services
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return services
    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc_el = port_el.find("service")
        services.append(
            Service(
                port=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", "tcp"),
                state="open",
                service=(svc_el.get("name") if svc_el is not None else "") or "",
                product=(svc_el.get("product") if svc_el is not None else "") or "",
                version=(svc_el.get("version") if svc_el is not None else "") or "",
            )
        )
    return services
