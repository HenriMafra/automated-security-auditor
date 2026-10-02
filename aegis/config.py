"""Run configuration and access to the vulnerability catalog."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = PROJECT_ROOT / "catalog" / "vulnerabilities.yaml"

# Ports probed by the native scanner when scope.allowed_ports is empty.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432,
    5601, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9200, 9300, 11211, 27017,
]


@dataclass(slots=True)
class RunConfig:
    """Everything a single assessment run needs, beyond the scope guard."""

    targets: list[str]
    out_dir: Path
    timeout: float = 10.0
    threads: int = 8
    user_agent: str = "Aegis/0.1 (+authorized-assessment)"
    ports: list[int] = field(default_factory=list)
    modules: list[str] | None = None  # None = all default modules
    enable_intrusive: bool = False


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    """Load and index the vulnerability catalog by id."""
    if not CATALOG_PATH.exists():
        return {"categories": [], "_index": {}}
    data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
    index: dict[str, dict[str, Any]] = {}
    for category in data.get("categories", []):
        for check in category.get("checks", []):
            cid = check.get("id")
            if cid:
                enriched = dict(check)
                enriched["category"] = category.get("name", "misc")
                enriched["owasp"] = category.get("owasp", "")
                index[cid] = enriched
    data["_index"] = index
    return data


def catalog_entry(catalog_id: str) -> dict[str, Any] | None:
    return load_catalog().get("_index", {}).get(catalog_id)
