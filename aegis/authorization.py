"""Authorization & scope guard — the heart of Aegis.

Nothing touches a target unless this module says the engagement is authorized,
in-window, and the target is in scope. There is intentionally **no override
flag**: to test something new you re-sign the authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import utils


class AuthorizationError(Exception):
    """Raised when an engagement cannot be authorized."""


@dataclass(slots=True)
class Scope:
    """The rules of engagement: what may be touched and how hard."""

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)  # empty = default top ports
    max_rps: float = 5.0
    allow_active: bool = True
    allow_intrusive: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        return cls(
            in_scope=[str(x) for x in data.get("in_scope", [])],
            out_of_scope=[str(x) for x in data.get("out_of_scope", [])],
            allowed_ports=[int(p) for p in data.get("allowed_ports", [])],
            max_rps=float(data.get("max_rps", 5.0)),
            allow_active=bool(data.get("allow_active", True)),
            allow_intrusive=bool(data.get("allow_intrusive", False)),
        )

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization used to compute the scope hash."""
        payload = {
            "in_scope": sorted(self.in_scope),
            "out_of_scope": sorted(self.out_of_scope),
            "allowed_ports": sorted(self.allowed_ports),
            "max_rps": self.max_rps,
            "allow_active": self.allow_active,
            "allow_intrusive": self.allow_intrusive,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(slots=True)
class Authorization:
    """A signed, time-boxed authorization document."""

    client: str
    authorized_by: str
    contact: str
    valid_from: datetime
    valid_until: datetime
    scope_hash: str
    signature: str = ""  # HMAC over (scope_hash|valid_from|valid_until) with a shared key
    engagement_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Authorization":
        return cls(
            client=str(data["client"]),
            authorized_by=str(data["authorized_by"]),
            contact=str(data.get("contact", "")),
            valid_from=_parse_dt(data["valid_from"]),
            valid_until=_parse_dt(data["valid_until"]),
            scope_hash=str(data.get("scope_hash", "")),
            signature=str(data.get("signature", "")),
            engagement_id=str(data.get("engagement_id", "")),
        )

    def signing_payload(self) -> bytes:
        return (
            f"{self.scope_hash}|{self.valid_from.isoformat()}|"
            f"{self.valid_until.isoformat()}"
        ).encode()

    def expected_signature(self, key: str) -> str:
        return hmac.new(key.encode(), self.signing_payload(), hashlib.sha256).hexdigest()


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(slots=True)
class ScopeGuard:
    """Combines an Authorization with its Scope and gates every target."""

    authorization: Authorization
    scope: Scope
    signing_key: str | None = None  # if set, signature is enforced

    # ---- construction -------------------------------------------------
    @classmethod
    def load(
        cls,
        auth_path: str | Path,
        scope_path: str | Path,
        signing_key: str | None = None,
    ) -> "ScopeGuard":
        auth_data = yaml.safe_load(Path(auth_path).read_text(encoding="utf-8")) or {}
        scope_data = yaml.safe_load(Path(scope_path).read_text(encoding="utf-8")) or {}
        return cls(
            authorization=Authorization.from_dict(auth_data),
            scope=Scope.from_dict(scope_data),
            signing_key=signing_key,
        )

    # ---- validation ---------------------------------------------------
    def validate(self) -> list[str]:
        """Full validation of the engagement itself (not a specific target).

        Returns a list of human-readable problems; empty list == valid.
        """
        problems: list[str] = []

        if not self.scope.in_scope:
            problems.append("scope.in_scope is empty — nothing is authorized")

        # scope_hash tamper check
        actual = self.scope.hash()
        if not self.authorization.scope_hash:
            problems.append("authorization has no scope_hash")
        elif not hmac.compare_digest(self.authorization.scope_hash, actual):
            problems.append(
                "scope_hash mismatch — scope.yaml was modified after signing "
                f"(auth={self.authorization.scope_hash[:12]}…, actual={actual[:12]}…)"
            )

        # time window
        now = datetime.now(timezone.utc)
        if now < self.authorization.valid_from:
            problems.append(
                f"engagement not yet valid (starts {self.authorization.valid_from.isoformat()})"
            )
        if now > self.authorization.valid_until:
            problems.append(
                f"authorization expired ({self.authorization.valid_until.isoformat()})"
            )

        # optional cryptographic signature
        if self.signing_key:
            expected = self.authorization.expected_signature(self.signing_key)
            if not self.authorization.signature:
                problems.append("signing key provided but authorization is unsigned")
            elif not hmac.compare_digest(self.authorization.signature, expected):
                problems.append("authorization signature is invalid")

        return problems

    def assert_valid(self) -> None:
        problems = self.validate()
        if problems:
            raise AuthorizationError(
                "Engagement is NOT authorized:\n  - " + "\n  - ".join(problems)
            )

    # ---- per-target gate ---------------------------------------------
    def target_reason(self, host: str) -> str | None:
        """Return a reason string if ``host`` is NOT allowed, else None."""
        # 1. explicit out-of-scope wins
        for pat in self.scope.out_of_scope:
            if utils.host_matches(host, pat):
                return f"'{host}' is explicitly out of scope ({pat})"

        # 2. direct hostname / wildcard match
        for pat in self.scope.in_scope:
            if utils.host_matches(host, pat):
                return None

        # 3. IP / CIDR match — resolve if needed
        candidates = [host] if utils.is_ip(host) else utils.resolve_host(host)
        cidr_scope = [s for s in self.scope.in_scope if utils.is_ip(s) or "/" in s]
        for ip in candidates:
            if utils.ip_in_networks(ip, cidr_scope):
                # also make sure it isn't out-of-scope by IP
                oob_cidrs = [
                    s for s in self.scope.out_of_scope if utils.is_ip(s) or "/" in s
                ]
                if utils.ip_in_networks(ip, oob_cidrs):
                    return f"'{host}' resolves to out-of-scope IP {ip}"
                return None

        return f"'{host}' is not covered by any in_scope entry"

    def is_authorized(self, host: str) -> bool:
        return self.target_reason(host) is None

    def check_activity(self, active: bool, intrusive: bool) -> str | None:
        """Return a reason if the requested activity level is not permitted."""
        if active and not self.scope.allow_active:
            return "active probing is disabled in scope (allow_active: false)"
        if intrusive and not self.scope.allow_intrusive:
            return "intrusive probing is disabled in scope (allow_intrusive: false)"
        return None
