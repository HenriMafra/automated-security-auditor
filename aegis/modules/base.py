"""Base contract every assessment module follows.

A module:
  * declares its ``name``, ``phase``, and whether it is ``active`` / ``intrusive``;
  * exposes ``available()`` so missing optional tooling is a skip, not a crash;
  * implements ``run(target, ctx)`` returning a list of Findings.

The engine wraps every ``run`` call so an exception in one module never aborts
the whole assessment — it is logged and the pipeline continues.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

from ..models import Finding, Target

if TYPE_CHECKING:  # avoid import cycle at runtime
    from ..engine import ScanContext


class Module(abc.ABC):
    #: short, unique identifier used on the CLI and in reports
    name: str = "base"
    #: human phase label for ordering/reporting
    phase: str = "misc"
    #: does this module send traffic to the target?
    active: bool = True
    #: does it send non-trivial / potentially noisy probes?
    intrusive: bool = False

    def available(self) -> tuple[bool, str]:
        """Return (is_available, reason). Default: always available."""
        return True, ""

    @abc.abstractmethod
    def run(self, target: Target, ctx: "ScanContext") -> list[Finding]:
        """Perform the module's work against ``target`` and return findings.

        Implementations should use ``ctx.session``/``ctx.rate`` for network I/O
        so rate limiting and the audit log are honored.
        """
        raise NotImplementedError
