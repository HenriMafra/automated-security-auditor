#!/usr/bin/env python3
"""Aegis loop health analysis — the every-100-iterations checkpoint.

Answers one question mechanically: **is the loop progressing or degrading?**

Reads HISTORY.md + STATE.json + the git log + a live `pytest` run, compares
against the previous checkpoint, and emits a verdict:

    HEALTHY    real, test-green progress; guardrails intact
    STALLING   flat: repeats, rising BLOCKED, no net tests / backlog burndown
    DEGRADING  regressions: fewer tests than last checkpoint, churn w/o value
    BROKEN     suite red, or a guarded baseline changed

Writes loop/health/checkpoint-<n>.md, updates STATE.health, and (with
--backend claude) writes a narrative analysis via `claude -p`.

Run `python loop/health_report.py --init` once to pin the guarded-path
baselines before the first autonomous run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LOOP_DIR = Path(__file__).resolve().parent
REPO = LOOP_DIR.parent
STATE_PATH = LOOP_DIR / "STATE.json"
HISTORY_PATH = LOOP_DIR / "HISTORY.md"
BASELINES_PATH = LOOP_DIR / ".baselines.json"
HEALTH_DIR = LOOP_DIR / "health"
METRICS_PATH = HEALTH_DIR / "metrics.json"

# Paths that must never drift under the autonomous loop.
GUARDED = [
    "aegis/authorization.py",
    "loop/PROTOCOL.md",
    "tests/test_authorization.py",
]

ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|\s*(T-\d+|[^|]*)\s*\|(.*)\|(.*)\|(.*)\|$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "MISSING"


def load_json(path: Path, default: dict) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


# --------------------------------------------------------------------------- #
# init: pin baselines
# --------------------------------------------------------------------------- #
def do_init() -> int:
    HEALTH_DIR.mkdir(exist_ok=True)
    (HEALTH_DIR / ".gitkeep").touch()
    guarded = {p: sha256_of(REPO / p) for p in GUARDED}
    BASELINES_PATH.write_text(
        json.dumps({"pinned_at": now_iso(), "guarded": guarded}, indent=2) + "\n",
        encoding="utf-8",
    )
    ok, count, _ = run_pytest()
    METRICS_PATH.write_text(
        json.dumps({"last_iteration": 0, "last_test_count": count,
                    "last_backlog_done": backlog_done_count()}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[health] baselines pinned for {len(guarded)} guarded paths; "
          f"tests={count} ({'green' if ok else 'RED'})")
    return 0


# --------------------------------------------------------------------------- #
# data collection
# --------------------------------------------------------------------------- #
def run_pytest() -> tuple[bool, int, str]:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q"],
                          cwd=REPO, capture_output=True, text=True)
    out = proc.stdout
    passed = sum(int(n) for n in re.findall(r"(\d+) passed", out))
    tail = out.strip().splitlines()[-1:] or [""]
    return proc.returncode == 0, passed, tail[0]


def parse_history() -> list[dict]:
    rows: list[dict] = []
    if not HISTORY_PATH.exists():
        return rows
    for line in HISTORY_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        if line.lower().startswith("| iteration"):
            continue
        parts = [c.strip() for c in line.strip("|").split("|")]
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        rows.append({"iteration": int(parts[0]), "task_id": parts[1],
                     "title": parts[2], "status": parts[3], "summary": parts[4]})
    return rows


def backlog_done_count() -> int:
    p = LOOP_DIR / "BACKLOG.md"
    if not p.exists():
        return 0
    return len(re.findall(r"-\s*\[x\]\s*T-\d+", p.read_text(encoding="utf-8"), re.I))


def guarded_drift() -> list[str]:
    base = load_json(BASELINES_PATH, {"guarded": {}}).get("guarded", {})
    drifted = []
    for path, expected in base.items():
        if sha256_of(REPO / path) != expected:
            drifted.append(path)
    return drifted


def git_churn(n_commits: int) -> tuple[int, int, int]:
    """(commits, insertions, deletions) over the last n_commits."""
    log = subprocess.run(["git", "log", f"-{max(1, n_commits)}", "--pretty=%H"],
                         cwd=REPO, capture_output=True, text=True)
    hashes = [h for h in log.stdout.split() if h]
    if not hashes:
        return 0, 0, 0
    oldest = hashes[-1]
    stat = subprocess.run(["git", "diff", "--shortstat", f"{oldest}~1", "HEAD"],
                          cwd=REPO, capture_output=True, text=True).stdout
    ins = sum(int(x) for x in re.findall(r"(\d+) insertion", stat))
    dele = sum(int(x) for x in re.findall(r"(\d+) deletion", stat))
    return len(hashes), ins, dele


# --------------------------------------------------------------------------- #
# verdict
# --------------------------------------------------------------------------- #
def compute(interval: int) -> dict:
    state = load_json(STATE_PATH, {})
    iteration = int(state.get("iteration", 0))
    rows = parse_history()
    window = [r for r in rows if r["iteration"] > iteration - interval]

    ready = sum(1 for r in window if r["status"] == "READY")
    blocked = sum(1 for r in window if r["status"] == "BLOCKED")
    auto_denied = sum(1 for r in window if r["status"] == "AUTO-DENIED")
    refused = sum(1 for r in window if r["status"] == "REFUSED")
    attempted = ready + blocked
    blocked_rate = round(blocked / attempted, 3) if attempted else 0.0
    distinct = len({r["task_id"] for r in window})
    repeats = len(window) - distinct

    ok, test_count, tests_line = run_pytest()
    drift = guarded_drift()
    prev = load_json(METRICS_PATH, {"last_test_count": test_count, "last_backlog_done": 0})
    delta_tests = test_count - int(prev.get("last_test_count", test_count))
    burndown = backlog_done_count() - int(prev.get("last_backlog_done", 0))
    commits, ins, dele = git_churn(len(window) or 1)

    # ---- verdict ----
    reasons: list[str] = []
    if not ok:
        verdict = "BROKEN"; reasons.append(f"pytest is RED ({tests_line})")
    elif drift:
        verdict = "BROKEN"; reasons.append(f"guarded baseline changed: {', '.join(drift)}")
    elif delta_tests < 0:
        verdict = "DEGRADING"; reasons.append(f"test count dropped by {-delta_tests}")
    elif window and ready == 0:
        verdict = "STALLING"; reasons.append("no READY iterations in this window")
    elif attempted and blocked_rate >= 0.5:
        verdict = "STALLING"; reasons.append(f"BLOCKED rate {blocked_rate:.0%}")
    elif window and burndown == 0 and delta_tests == 0:
        verdict = "STALLING"; reasons.append("no backlog burndown and no net tests")
    elif window and repeats > distinct:
        verdict = "STALLING"; reasons.append(f"{repeats} repeated task ids (thrashing)")
    else:
        verdict = "HEALTHY"
        reasons.append(f"{ready} tasks landed, +{delta_tests} tests, "
                       f"{burndown} backlog items burned down")

    return {
        "iteration": iteration, "window": len(window),
        "ready": ready, "blocked": blocked, "auto_denied": auto_denied,
        "refused": refused, "blocked_rate": blocked_rate,
        "distinct_tasks": distinct, "repeats": repeats,
        "tests_ok": ok, "test_count": test_count, "delta_tests": delta_tests,
        "tests_line": tests_line, "guarded_drift": drift,
        "backlog_burndown": burndown, "commits": commits,
        "insertions": ins, "deletions": dele,
        "verdict": verdict, "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def write_report(m: dict) -> Path:
    HEALTH_DIR.mkdir(exist_ok=True)
    n = m["iteration"]
    path = HEALTH_DIR / f"checkpoint-{n}.md"
    lines = [
        f"# Health checkpoint — iteration {n}",
        "", f"**Verdict: {m['verdict']}**  ·  generated {now_iso()}", "",
        "## Why", *[f"- {r}" for r in m["reasons"]], "",
        "## Metrics (this window)", "",
        "| Metric | Value |", "|--------|-------|",
        f"| Iterations in window | {m['window']} |",
        f"| READY | {m['ready']} |",
        f"| BLOCKED | {m['blocked']} (rate {m['blocked_rate']:.0%}) |",
        f"| AUTO-DENIED | {m['auto_denied']} |",
        f"| REFUSED | {m['refused']} |",
        f"| Distinct tasks / repeats | {m['distinct_tasks']} / {m['repeats']} |",
        f"| Tests | {m['test_count']} ({'green' if m['tests_ok'] else 'RED'}), "
        f"Δ {m['delta_tests']:+d} |",
        f"| Backlog burndown | {m['backlog_burndown']} |",
        f"| Commits / churn | {m['commits']} / +{m['insertions']} −{m['deletions']} |",
        f"| Guarded drift | {', '.join(m['guarded_drift']) or 'none'} |",
        "",
        "## Recommendation", "",
        _recommendation(m["verdict"]),
        "",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _recommendation(verdict: str) -> str:
    return {
        "HEALTHY": "Loop is progressing. Safe to auto-continue.",
        "STALLING": "Progress has flattened. **Halt** and review the backlog / "
                    "task framing before continuing.",
        "DEGRADING": "Quality is regressing. **Halt**, inspect the last window's "
                     "commits, and revert the offending changes.",
        "BROKEN": "**Halt immediately.** The suite is red or a guarded file "
                  "changed. Investigate before any further iterations.",
    }.get(verdict, "Review manually.")


def maybe_narrative(m: dict, backend: str) -> None:
    if backend != "claude":
        return
    try:
        prompt = ("You are the analyst for the Aegis autonomous dev loop. Given "
                  "these checkpoint metrics, write a concise (max ~200 words) "
                  "narrative: is it genuinely progressing or degrading, what is "
                  "the single biggest risk, and one concrete recommendation.\n\n"
                  + json.dumps(m, indent=2))
        proc = subprocess.run(["claude", "-p", prompt], cwd=REPO,
                              capture_output=True, text=True, timeout=180)
        if proc.returncode == 0 and proc.stdout.strip():
            (HEALTH_DIR / f"checkpoint-{m['iteration']}.analysis.md").write_text(
                proc.stdout.strip() + "\n", encoding="utf-8")
    except Exception:
        pass  # narrative is best-effort; metrics + verdict already written


def update_state(m: dict) -> None:
    state = load_json(STATE_PATH, {})
    state.setdefault("health", {})
    state["health"] = {"last_checkpoint": m["iteration"],
                       "verdict": m["verdict"], "checked_at": now_iso()}
    state["last_updated"] = now_iso()
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    METRICS_PATH.write_text(
        json.dumps({"last_iteration": m["iteration"],
                    "last_test_count": m["test_count"],
                    "last_backlog_done": backlog_done_count()}, indent=2) + "\n",
        encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aegis loop health analysis")
    ap.add_argument("--init", action="store_true", help="pin guarded baselines and exit")
    ap.add_argument("--backend", choices=["dry-run", "claude"], default="dry-run")
    ap.add_argument("--interval", type=int, default=None, help="window size override")
    args = ap.parse_args(argv)

    if args.init:
        return do_init()

    state = load_json(STATE_PATH, {})
    interval = args.interval or int(state.get("checkpoint_interval", 100))
    m = compute(interval)
    path = write_report(m)
    maybe_narrative(m, args.backend)
    update_state(m)
    print(f"[health] iteration {m['iteration']}: {m['verdict']} — {'; '.join(m['reasons'])}")
    print(f"[health] report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
