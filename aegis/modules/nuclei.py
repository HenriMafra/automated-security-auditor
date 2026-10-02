"""Optional integration with ProjectDiscovery's ``nuclei``.

This module is marked *intrusive* because template-based scanning sends many
probes. It only runs when (a) ``nuclei`` is installed, (b) the scope allows
intrusive activity, and (c) the run was started with intrusive enabled.
"""

from __future__ import annotations

import json
import subprocess

from .. import utils
from ..models import Confidence, Finding, Severity, Target
from .base import Module

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


class NucleiModule(Module):
    name = "nuclei"
    phase = "vuln"
    active = True
    intrusive = True

    def available(self) -> tuple[bool, str]:
        if not utils.have_tool("nuclei"):
            return False, "nuclei binary not found on PATH"
        return True, ""

    def run(self, target: Target, ctx) -> list[Finding]:
        url = target.urls[0] if target.urls else target.base_url()
        cmd = [
            "nuclei", "-u", url, "-jsonl", "-silent",
            "-rate-limit", str(int(max(1, ctx.guard.scope.max_rps))),
            "-severity", "low,medium,high,critical",
            "-timeout", str(int(ctx.config.timeout)),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800
            )
        except (subprocess.SubprocessError, OSError) as exc:
            utils.warn(f"    nuclei execution failed: {exc}")
            return []

        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._to_finding(data, target))
        return findings

    def _to_finding(self, data: dict, target: Target) -> Finding:
        info = data.get("info", {})
        sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        return Finding(
            title=info.get("name", data.get("template-id", "nuclei finding")),
            severity=sev,
            module=self.name,
            target=target.host,
            category="Nuclei detection",
            catalog_id="AEG-NUCLEI",
            confidence=Confidence.FIRM,
            description=info.get("description", "") or "Template-based detection.",
            evidence=f"matched-at: {data.get('matched-at', data.get('host', ''))}",
            remediation=info.get("remediation", "Review and remediate per template guidance."),
            references=list(refs),
        )
