"""Command-line interface: ``aegis verify | run | catalog``."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, utils
from .authorization import AuthorizationError, ScopeGuard
from .config import RunConfig, load_catalog
from .engine import Engine
from .reporting import write_reports


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — Authorized Security Assessment Framework",
    )
    p.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # verify
    v = sub.add_parser("verify", help="Validate authorization + scope, no scanning")
    v.add_argument("--auth", required=True)
    v.add_argument("--scope", required=True)
    v.add_argument("--signing-key", default=None, help="enforce HMAC signature")
    v.add_argument("--target", action="append", default=[], help="test a host against scope")

    # run
    r = sub.add_parser("run", help="Run an authorized assessment")
    r.add_argument("--auth", required=True)
    r.add_argument("--scope", required=True)
    r.add_argument("--signing-key", default=None)
    r.add_argument("--target", action="append", default=[], required=True)
    r.add_argument("--out", default="reports")
    r.add_argument("--modules", default=None, help="comma-separated module subset")
    r.add_argument("--timeout", type=float, default=10.0)
    r.add_argument(
        "--enable-intrusive",
        action="store_true",
        help="allow intrusive modules (also requires scope allow_intrusive)",
    )

    # catalog
    c = sub.add_parser("catalog", help="List/search the vulnerability catalog")
    c.add_argument("--search", default=None, help="filter by keyword")

    return p


def _cmd_verify(args) -> int:
    guard = ScopeGuard.load(args.auth, args.scope, signing_key=args.signing_key)
    problems = guard.validate()
    if problems:
        utils.err("Authorization INVALID:")
        for pr in problems:
            utils.err(f"  - {pr}")
        return 1
    utils.good("Authorization is VALID and in-window.")
    utils.info(f"  Client: {guard.authorization.client}")
    utils.info(f"  Window: {guard.authorization.valid_from.isoformat()} "
               f"→ {guard.authorization.valid_until.isoformat()}")
    utils.info(f"  In scope: {', '.join(guard.scope.in_scope)}")
    for t in args.target:
        reason = guard.target_reason(t)
        if reason:
            utils.warn(f"  {t}: NOT authorized — {reason}")
        else:
            utils.good(f"  {t}: authorized")
    return 0


def _cmd_run(args) -> int:
    guard = ScopeGuard.load(args.auth, args.scope, signing_key=args.signing_key)
    try:
        guard.assert_valid()
    except AuthorizationError as exc:
        utils.err(str(exc))
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) / stamp
    modules = [m.strip() for m in args.modules.split(",")] if args.modules else None

    config = RunConfig(
        targets=args.target,
        out_dir=out_dir,
        timeout=args.timeout,
        modules=modules,
        enable_intrusive=args.enable_intrusive,
    )
    engine = Engine(guard, config)
    findings = engine.run()
    paths = write_reports(findings, guard, out_dir)
    utils.good("Reports written:")
    for kind, path in paths.items():
        utils.info(f"  {kind}: {path}")
    return 0


def _cmd_catalog(args) -> int:
    catalog = load_catalog()
    term = (args.search or "").lower()
    total = 0
    for category in catalog.get("categories", []):
        checks = category.get("checks", [])
        shown = [
            c for c in checks
            if not term
            or term in category.get("name", "").lower()
            or term in c.get("id", "").lower()
            or term in c.get("title", "").lower()
            or term in " ".join(c.get("techniques", [])).lower()
        ]
        if not shown:
            continue
        owasp = category.get("owasp", "")
        utils.log(f"\n== {category.get('name')} {('['+owasp+']') if owasp else ''} ==",
                  style="bold")
        for c in shown:
            total += 1
            utils.log(f"  {c.get('id'):<16} [{c.get('severity','?'):<8}] {c.get('title')}")
    utils.info(f"\n{total} catalog check(s) listed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "catalog":
            return _cmd_catalog(args)
    except FileNotFoundError as exc:
        utils.err(f"File not found: {exc}")
        return 2
    except AuthorizationError as exc:
        utils.err(str(exc))
        return 1
    except KeyboardInterrupt:
        utils.warn("Interrupted.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
