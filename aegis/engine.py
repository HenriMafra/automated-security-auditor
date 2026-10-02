"""The orchestration engine: wires scope guard + modules + reporting together.

Design goals:
  * **Fail-safe, not fail-stop** — one module raising never aborts the run.
  * **Auditable** — every HTTP request is logged to ``evidence.log``.
  * **Polite** — all network I/O passes through a shared rate limiter.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

from . import utils
from .authorization import ScopeGuard
from .config import RunConfig
from .models import Finding, Target
from .modules.base import Module


@dataclass
class ScanContext:
    """Shared state handed to every module during a run."""

    guard: ScopeGuard
    config: RunConfig
    session: requests.Session
    rate: utils.RateLimiter
    evidence_path: Path
    findings: list[Finding] = field(default_factory=list)

    def request(self, method: str, url: str, **kwargs) -> requests.Response | None:
        """Rate-limited, logged HTTP request. Returns None on network error."""
        self.rate.acquire()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)  # target certs may be self-signed
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("User-Agent", self.config.user_agent)
        try:
            resp = self.session.request(method, url, headers=headers, **kwargs)
        except requests.RequestException as exc:
            self._log_evidence(method, url, error=str(exc))
            return None
        self._log_evidence(method, url, status=resp.status_code)
        return resp

    def _log_evidence(
        self, method: str, url: str, status: int | None = None, error: str = ""
    ) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "error": error,
        }
        with self.evidence_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


class Engine:
    def __init__(self, guard: ScopeGuard, config: RunConfig) -> None:
        self.guard = guard
        self.config = config

    def _select_modules(self) -> list[Module]:
        # Imported here to avoid import cycles and to keep optional deps lazy.
        from .modules.fingerprint import FingerprintModule
        from .modules.nuclei import NucleiModule
        from .modules.portscan import PortScanModule
        from .modules.recon import ReconModule
        from .modules.tls_check import TlsModule
        from .modules.web_headers import WebHeadersModule

        registry: list[Module] = [
            ReconModule(),
            PortScanModule(),
            TlsModule(),
            FingerprintModule(),
            WebHeadersModule(),
            NucleiModule(),
        ]

        wanted = self.config.modules
        if wanted:
            registry = [m for m in registry if m.name in wanted]
        return registry

    def run(self) -> list[Finding]:
        # 1. Engagement-level authorization must pass, or we don't start.
        self.guard.assert_valid()

        out_dir = self.config.out_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = out_dir / "evidence.log"
        evidence_path.write_text("", encoding="utf-8")

        session = requests.Session()
        # Silence only the self-signed-cert warning we deliberately opt into.
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        rate = utils.RateLimiter(self.guard.scope.max_rps)
        ctx = ScanContext(
            guard=self.guard,
            config=self.config,
            session=session,
            rate=rate,
            evidence_path=evidence_path,
        )

        modules = self._select_modules()
        utils.info(
            f"Loaded {len(modules)} modules: {', '.join(m.name for m in modules)}"
        )

        for raw_host in self.config.targets:
            host = _normalize_host(raw_host)

            reason = self.guard.target_reason(host)
            if reason:
                utils.warn(f"SKIP {host}: {reason}")
                continue

            utils.good(f"Target authorized: {host}")
            target = Target(host=host)
            ips = utils.resolve_host(host)
            target.resolved_ips = ips
            target.ip = ips[0] if ips else None

            for module in modules:
                self._run_one(module, target, ctx)

        utils.info(f"Assessment complete — {len(ctx.findings)} findings collected")
        return _dedupe(ctx.findings)

    def _run_one(self, module: Module, target: Target, ctx: ScanContext) -> None:
        # Activity-level gate (active/intrusive) from the signed scope.
        activity_reason = ctx.guard.check_activity(module.active, module.intrusive)
        if activity_reason:
            utils.warn(f"  [{module.name}] skipped: {activity_reason}")
            return
        if module.intrusive and not ctx.config.enable_intrusive:
            utils.warn(f"  [{module.name}] skipped: intrusive not enabled for this run")
            return

        ok, why = module.available()
        if not ok:
            utils.warn(f"  [{module.name}] unavailable: {why} (continuing)")
            return

        try:
            start = time.monotonic()
            found = module.run(target, ctx)
            elapsed = time.monotonic() - start
            ctx.findings.extend(found)
            utils.info(
                f"  [{module.name}] {len(found)} finding(s) in {elapsed:0.1f}s"
            )
        except Exception as exc:  # fail-safe: never abort the whole run
            utils.err(f"  [{module.name}] error: {exc!r} (skipped)")


def _normalize_host(raw: str) -> str:
    raw = raw.strip()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    return raw.split("/")[0].split(":")[0].rstrip(".")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.key, f)
    ordered = sorted(
        seen.values(), key=lambda f: (int(f.severity), f.category), reverse=True
    )
    return ordered
