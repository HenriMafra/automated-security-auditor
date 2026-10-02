"""Core data models shared across the framework."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels (higher = worse). IntEnum so we can sort."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    def label(self) -> str:
        return self.name.capitalize()


class Confidence(enum.Enum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


@dataclass(slots=True)
class Finding:
    """A single observation produced by a module.

    ``key`` is used for deduplication: two findings with the same key are the
    same issue on the same asset.
    """

    title: str
    severity: Severity
    module: str
    target: str
    category: str = "misc"
    catalog_id: str | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.FIRM
    references: list[str] = field(default_factory=list)
    cvss: float | None = None
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def key(self) -> str:
        raw = f"{self.category}|{self.title}|{self.target}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.label()
        d["confidence"] = self.confidence.value
        d["key"] = self.key
        return d


@dataclass(slots=True)
class Service:
    """A discovered network service."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class Target:
    """The asset under assessment plus everything we learn about it."""

    host: str
    ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def base_url(self, prefer_https: bool = True) -> str:
        scheme = "https" if prefer_https else "http"
        return f"{scheme}://{self.host}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ip": self.ip,
            "resolved_ips": self.resolved_ips,
            "services": [s.to_dict() for s in self.services],
            "urls": self.urls,
            "metadata": self.metadata,
        }
