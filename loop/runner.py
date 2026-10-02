#!/usr/bin/env python3
"""Aegis autonomous loop runner.

Drives the prompt loop with NO human in the per-iteration path:

    Planner  = loop/BACKLOG.md   (next unchecked item = next task)
    Executor = `claude -p` headless (or --backend dry-run for a no-op test)
    Courier  = this script

Safety model (see loop/PROTOCOL.md, especially Sections 6, 7.1, 9):
  * Refuses to start on a dirty git tree (protects your uncommitted work).
  * Runs `python -m pytest` after every iteration; a red suite reverts the
    iteration (`git reset --hard` + `git clean -fd`) and marks it BLOCKED.
  * Reverts + logs AUTO-DENIED if an iteration's diff touches a guarded path
    (aegis/authorization.py, loop/PROTOCOL.md, ... — pinned in .baselines.json).
  * REFUSES backlog items matching a forbidden feature class.
  * The ONLY outward action it performs is `git push origin <branch>` to the
    already-configured `origin` remote, after every commit (each iteration,
    each health checkpoint, each stop). It never creates a remote, never
    changes credentials, and a failed push just logs a warning and keeps the
    loop running locally — nothing else is irreversible or destructive.
  * Every `checkpoint_interval` iterations runs the health analysis and HALTS
    unless the verdict is HEALTHY.

This is a power tool. Default is a single iteration (`--once`); you must pass
`--auto` to let it run unattended, and `--backend claude` to let it actually
change code (default backend is a safe dry-run). Every iteration is committed
AND PUSHED to GitHub as it happens — the remote is always the live mirror of
the local state, documented via HISTORY.md/OUTBOX.md and the health/ reports.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LOOP_DIR = Path(__file__).resolve().parent
REPO = LOOP_DIR.parent
STATE_PATH = LOOP_DIR / "STATE.json"
BACKLOG_PATH = LOOP_DIR / "BACKLOG.md"
HISTORY_PATH = LOOP_DIR / "HISTORY.md"
INBOX_PATH = LOOP_DIR / "INBOX.md"
OUTBOX_PATH = LOOP_DIR / "OUTBOX.md"
BASELINES_PATH = LOOP_DIR / ".baselines.json"
DRY_NOTES = LOOP_DIR / "dry_run_notes.md"

# Backlog items whose text matches any of these are REFUSED (never executed).
FORBIDDEN_PATTERNS = [
    r"\bddos\b", r"\bdos\b", r"denial[- ]of[- ]service", r"\bflood(ing)?\b",
    r"reverse shell", r"\bmalware\b", r"\bransomware\b", r"\bexfiltrat",
    r"delete .*(data|database|records)", r"deface", r"\bpersistence\b",
    r"detection[- ]evasion", r"\bevade\b .*detection", r"\bbotnet\b",
    r"mass[- ]target", r"indiscriminate", r"bypass .*authorization",
    r"weaken .*(guard|authorization|scope)", r"disable .*(guard|auth)",
]

TASK_ID_RE = re.compile(r"^-\s*\[ \]\s*(T-\d+)\b(.*)$")
DONE_ID_RE = re.compile(r"^-\s*\[x\]\s*(T-\d+)\b", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# small utilities
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    print(f"[runner] {msg}", flush=True)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=check
    )


def load_state() -> dict:
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def save_state(state: dict) -> None:
    state["last_updated"] = now_iso()
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def tree_is_clean() -> bool:
    return git("status", "--porcelain").stdout.strip() == ""


def head_rev() -> str:
    return git("rev-parse", "HEAD").stdout.strip()


def revert_to(rev: str) -> None:
    git("reset", "--hard", rev, check=False)
    git("clean", "-fd", check=False)


def push(quiet_ok: bool = True) -> bool:
    """Push the current branch to origin. Never fatal — a push failure (e.g.
    offline, no remote configured, transient auth issue) is logged and the
    loop keeps running locally; the next successful push carries everything.
    """
    branch = git("rev-parse", "--abbrev-ref", "HEAD", check=False).stdout.strip()
    proc = git("push", "origin", branch, check=False)
    if proc.returncode != 0:
        log(f"WARNING: push failed (will retry next iteration): "
            f"{proc.stderr.strip()[:200]}")
        return False
    if not quiet_ok:
        log(f"pushed to origin/{branch}")
    return True


# --------------------------------------------------------------------------- #
# baselines (guarded paths)
# --------------------------------------------------------------------------- #
def load_baselines() -> dict:
    if not BASELINES_PATH.exists():
        return {"guarded": {}}
    return json.loads(BASELINES_PATH.read_text(encoding="utf-8"))


def guarded_paths_touched(base_rev: str) -> list[str]:
    """Return guarded repo paths whose content changed since base_rev."""
    guarded = set(load_baselines().get("guarded", {}).keys())
    if not guarded:
        return []
    diff = git("diff", "--name-only", base_rev, "HEAD", check=False).stdout
    working = git("status", "--porcelain").stdout
    changed = set()
    for line in diff.splitlines():
        changed.add(line.strip())
    for line in working.splitlines():
        changed.add(line[3:].strip())
    return sorted(p for p in changed if p in guarded)


# --------------------------------------------------------------------------- #
# backlog (the Planner)
# --------------------------------------------------------------------------- #
def next_backlog_item() -> tuple[str, str] | None:
    for line in BACKLOG_PATH.read_text(encoding="utf-8").splitlines():
        m = TASK_ID_RE.match(line.strip())
        if m:
            return m.group(1), (m.group(1) + m.group(2)).strip()
    return None


def mark_backlog_done(task_id: str) -> None:
    lines = BACKLOG_PATH.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        m = TASK_ID_RE.match(line.strip())
        if m and m.group(1) == task_id:
            out.append(line.replace("- [ ]", "- [x]", 1))
        else:
            out.append(line)
    BACKLOG_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def is_forbidden(text: str) -> str | None:
    low = text.lower()
    for pat in FORBIDDEN_PATTERNS:
        if re.search(pat, low):
            return pat
    return None


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
def run_pytest() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=REPO, capture_output=True, text=True,
    )
    tail = proc.stdout.strip().splitlines()[-1:] or [""]
    return proc.returncode == 0, tail[0]


# --------------------------------------------------------------------------- #
# executor backends
# --------------------------------------------------------------------------- #
def execute_dry_run(task_id: str, task: str) -> str:
    """No-op backend: records the intent so the pipeline has a change to commit."""
    stamp = now_iso()
    with DRY_NOTES.open("a", encoding="utf-8") as fh:
        fh.write(f"- {stamp} {task_id}: {task}\n")
    return "dry-run: recorded intent, no code change"


def execute_claude(task_id: str, task: str) -> str:
    """Real backend: one focused, additive implementation via `claude -p`."""
    prompt = (
        "You are the Executor in the Aegis autonomous loop. Implement EXACTLY "
        f"this one backlog item, additively, and nothing else:\n\n{task}\n\n"
        "Hard rules: keep `python -m pytest` green; do NOT edit "
        "aegis/authorization.py, loop/PROTOCOL.md, or any guardrail; no network "
        "calls, no git push; prefer new files (tests/modules/docs). When done, "
        "print a one-line summary of what you changed."
    )
    proc = subprocess.run(
        ["claude", "-p", prompt],
        cwd=REPO, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude backend failed: {proc.stderr.strip()[:300]}")
    return (proc.stdout.strip().splitlines()[-1:] or ["claude: done"])[0]


BACKENDS = {"dry-run": execute_dry_run, "claude": execute_claude}


# --------------------------------------------------------------------------- #
# history / mirrors
# --------------------------------------------------------------------------- #
def append_history(iteration: int, task_id: str, title: str, status: str, summary: str) -> None:
    row = f"| {iteration} | {task_id} | {_esc(title)} | {status} | {_esc(summary)} |\n"
    with HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(row)


def _esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()[:200]


def write_mirrors(iteration: int, task_id: str, task: str, status: str,
                  tests: str, summary: str) -> None:
    INBOX_PATH.write_text(
        f"# INBOX\n\n```\n===AEGIS-TASK v1===\nITERATION: {iteration}\n"
        f"TASK_ID: {task_id}\nOBJECTIVE: backlog burndown\nTASK: {task}\n"
        f"ACCEPTANCE: pytest green; additive only\nCONSTRAINTS: additive-only\n"
        f"===END-TASK===\n```\n", encoding="utf-8")
    OUTBOX_PATH.write_text(
        f"# OUTBOX\n\n```\n===AEGIS-REPORT v1===\nITERATION: {iteration}\n"
        f"TASK_ID: {task_id}\nSTATUS: {status}\nSUMMARY: {summary}\n"
        f"TESTS: {tests}\n===END-REPORT===\n```\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# one iteration
# --------------------------------------------------------------------------- #
def run_iteration(state: dict, backend: str) -> str:
    """Execute one iteration. Returns a control signal: 'continue' | 'stop'."""
    item = next_backlog_item()
    if item is None:
        state["status"] = "STOPPED"
        state["stop_reason"] = "backlog-empty"
        save_state(state)
        git("add", "loop", check=False)
        git("commit", "-m", "loop stopped: backlog-empty", check=False)
        push()
        log("backlog empty — stopping")
        return "stop"

    task_id, task = item
    iteration = state["iteration"] + 1
    log(f"iteration {iteration}: {task_id}")

    # Forbidden feature class → refuse, do not execute, move on.
    hit = is_forbidden(task)
    if hit:
        state["iteration"] = iteration
        state["refused_count"] = state.get("refused_count", 0) + 1
        save_state(state)
        append_history(iteration, task_id, task, "REFUSED", f"matched forbidden pattern /{hit}/")
        mark_backlog_done(task_id)  # tick so we don't loop on it
        git("add", "-A", check=False)
        git("commit", "-m", f"loop {iteration}: REFUSE {task_id}", check=False)
        push()
        log(f"REFUSED {task_id} (forbidden: {hit})")
        return "continue"

    base_rev = head_rev()
    status = "READY"
    try:
        summary = BACKENDS[backend](task_id, task)
    except Exception as exc:  # backend failure → blocked, revert
        revert_to(base_rev)
        summary = f"backend error: {exc}"[:200]
        status = "BLOCKED"

    tests_line = "not run"
    if status == "READY":
        touched = guarded_paths_touched(base_rev)
        if touched:
            revert_to(base_rev)
            status = "AUTO-DENIED"
            summary = f"iteration touched guarded path(s): {', '.join(touched)}"
            state["auto_denied_count"] = state.get("auto_denied_count", 0) + 1
        else:
            ok, tests_line = run_pytest()
            if not ok:
                revert_to(base_rev)
                status = "BLOCKED"
                summary = f"tests failed and were reverted ({tests_line})"

    # blocked_streak bookkeeping
    if status in ("BLOCKED", "AUTO-DENIED"):
        if state.get("last_task_id") == task_id:
            state["blocked_streak"] = state.get("blocked_streak", 0) + 1
        else:
            state["blocked_streak"] = 1
    else:
        state["blocked_streak"] = 0

    state["iteration"] = iteration
    state["last_task_id"] = task_id

    if status == "READY":
        mark_backlog_done(task_id)
        write_mirrors(iteration, task_id, task, status, tests_line, summary)
        append_history(iteration, task_id, task, status, summary)
        save_state(state)
        git("add", "-A", check=False)
        git("commit", "-m", f"loop {iteration}: {task_id} READY — {summary[:72]}", check=False)
    else:
        write_mirrors(iteration, task_id, task, status, tests_line, summary)
        append_history(iteration, task_id, task, status, summary)
        save_state(state)
        # record the run itself (mirrors/state) even though code was reverted
        git("add", "loop", check=False)
        git("commit", "-m", f"loop {iteration}: {task_id} {status} — {summary[:72]}", check=False)

    push()
    log(f"iteration {iteration}: {status} — {summary[:80]}")

    # stuck-task stop
    if state["blocked_streak"] >= 2:
        state["status"] = "STOPPED"
        state["stop_reason"] = f"blocked-twice:{task_id}"
        save_state(state)
        git("add", "loop", check=False)
        git("commit", "-m", f"loop stopped: {task_id} blocked twice", check=False)
        push()
        log(f"stopping — {task_id} blocked twice")
        return "stop"

    return "continue"


def do_checkpoint(state: dict, backend: str) -> str:
    """Run the health analysis and gate. Returns 'continue' | 'stop'."""
    log(f"health checkpoint at iteration {state['iteration']}")
    proc = subprocess.run(
        [sys.executable, str(LOOP_DIR / "health_report.py"),
         "--backend", backend],
        cwd=REPO, capture_output=True, text=True,
    )
    print(proc.stdout, flush=True)
    state = load_state()  # health_report updated it
    verdict = state.get("health", {}).get("verdict", "UNKNOWN")

    git("add", "loop", check=False)
    git("commit", "-m", f"loop checkpoint at iteration {state['iteration']}: {verdict}",
        check=False)
    push()

    if verdict != "HEALTHY":
        state["status"] = "STOPPED"
        state["stop_reason"] = f"health:{verdict}"
        save_state(state)
        git("add", "loop", check=False)
        git("commit", "-m", f"loop stopped: health={verdict}", check=False)
        push()
        log(f"stopping — health verdict {verdict}")
        return "stop"
    log("health HEALTHY — continuing")
    return "continue"


# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aegis autonomous loop runner")
    ap.add_argument("--backend", choices=list(BACKENDS), default="dry-run",
                    help="executor backend (default: dry-run / safe no-op)")
    ap.add_argument("--auto", action="store_true",
                    help="run continuously until a stop condition (default: one iteration)")
    ap.add_argument("--once", action="store_true", help="run exactly one iteration (default)")
    ap.add_argument("--max-iterations", type=int, default=None,
                    help="override STATE.max_iterations for this run")
    args = ap.parse_args(argv)

    if not (REPO / ".git").exists():
        log("ERROR: not a git repository — the runner needs git for safe reverts")
        return 2
    if not tree_is_clean():
        log("ERROR: git working tree is dirty. Commit or stash your changes first.")
        return 2
    if not BASELINES_PATH.exists():
        log("ERROR: loop/.baselines.json missing. Run: python loop/health_report.py --init")
        return 2

    state = load_state()
    if args.max_iterations is not None:
        state["max_iterations"] = args.max_iterations
    if state.get("status") == "STOPPED":
        log(f"state is STOPPED (reason: {state.get('stop_reason')}). "
            "Clear stop_reason / refill BACKLOG to resume.")
        return 1
    state["status"] = "RUNNING"
    save_state(state)

    interval = int(state.get("checkpoint_interval", 100))
    cap = int(state.get("max_iterations", 1000))
    single = not args.auto

    while True:
        if state["iteration"] >= cap:
            state["status"] = "STOPPED"
            state["stop_reason"] = "max-iterations"
            save_state(state)
            git("add", "loop", check=False)
            git("commit", "-m", f"loop stopped: max-iterations ({cap})", check=False)
            push()
            log(f"reached max_iterations={cap} — stopping")
            break

        signal = run_iteration(state, args.backend)
        state = load_state()
        if signal == "stop":
            break

        if state["iteration"] % interval == 0:
            if do_checkpoint(state, args.backend) == "stop":
                break
            state = load_state()

        if single:
            state["status"] = "PAUSED"
            state["stop_reason"] = None
            save_state(state)
            git("add", "loop", check=False)
            git("commit", "-m", f"loop {state['iteration']}: paused after --once", check=False)
            push()
            log("single iteration done (pass --auto to run continuously)")
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
