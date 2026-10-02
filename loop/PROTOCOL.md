# AEGIS Prompt-Loop Contract (v1)

`loop/PROTOCOL.md` — the durable, versioned source of truth for the AEGIS
iteration loop. **This file _is_ the contract.** If any other document disagrees
with it, this file wins.

> **Safety-critical / immutable clauses.** Sections 6 (Rules & Guardrails) and
> the forbidden-feature list, together with `aegis/authorization.py`, form the
> product's safety core. They may only be changed with **explicit human
> approval** (Rule 5). No TASK may weaken them, and a TASK that edits them
> pauses for human sign-off — it is never executed as an ordinary task.

---

## 1. Purpose

AEGIS drives the project at `C:/aegis-pentest` through a tight, auditable loop
between two AIs and one human. Each iteration produces exactly one focused
change, keeps the test suite green, and leaves a written trail so the next
iteration can be planned without repetition or scope drift.

---

## 2. Roles

| Role | Who | Responsibility |
|------|-----|----------------|
| **PLANNER** | An external AI | Produces exactly **ONE** task per iteration; decides when the objective is complete and ends the loop. |
| **EXECUTOR** | Claude Code, inside `C:/aegis-pentest` | Executes the task, edits files, runs tests, reports back; enforces the guardrails and the iteration cap. |
| **COURIER** | The human user | Relays the sentinel blocks between the two AIs; holds approval authority. |

The Planner and Executor never talk directly. Every message passes through the
Courier as a copy-pasted sentinel block (see [Section 5](#5-courier-model)).

---

## 3. Repository files

The Executor keeps these as the durable, versioned mirror of loop state:

| File | Role |
|------|------|
| `loop/PROTOCOL.md` | This contract. |
| `loop/INBOX.md` | The latest **TASK** block received from the Planner. |
| `loop/OUTBOX.md` | The latest **REPORT** block produced by the Executor. |
| `loop/HISTORY.md` | Append-only log: iteration, task id, title, status, one-line summary. |
| `loop/STATE.json` | `{ protocol_version, iteration, max_iterations, status, last_task_id, blocked_streak, last_updated }`. |

---

## 4. Handshake — verbatim sentinels

Reproduce the opening and closing markers **exactly** — no extra spaces, no
renamed fields — so each side can reliably parse the other's message. There are
**three** block types.

### 4.1 PLANNER → EXECUTOR — a task

```
===AEGIS-TASK v1===
ITERATION: <n>
TASK_ID: <stable id, e.g. T-003 — REUSE the same id when retrying a task>
OBJECTIVE: <the standing goal this iteration serves>
TASK: <one focused, concrete change or investigation>
ACCEPTANCE: <observable criteria that mean "done">
CONSTRAINTS: <optional extra limits>
===END-TASK===
```

`TASK_ID` gives tasks a stable identity. When the Planner retries a task that
came back `BLOCKED`, it MUST reuse the same `TASK_ID`; a genuinely new task gets
a new id.

### 4.2 EXECUTOR → PLANNER — a report

```
===AEGIS-REPORT v1===
ITERATION: <n>
TASK_ID: <echoes the TASK_ID this report answers>
STATUS: READY | BLOCKED | DONE
SUMMARY: <what was actually done>
CHANGED_FILES: <list, or "none">
TESTS: <pytest result, e.g. "12 passed">
NOTES: <risks, decisions, follow-ups>
NEXT_INPUT_FOR_PLANNER: <the concise state the Planner needs to plan iteration n+1>
===END-REPORT===
```

**STATUS meaning:**
- `READY` — task complete, `pytest` green, ready for the next iteration.
- `BLOCKED` — task could not be completed this iteration; reason in `NOTES`.
- `DONE` — the Executor judges the standing **OBJECTIVE** fully achieved and
  recommends the Planner end the loop (emit an `===AEGIS-STOP v1===` block) or
  set a **new** OBJECTIVE.

### 4.3 PLANNER → EXECUTOR — end the loop

The **only** valid way to terminate. (There is deliberately no `STATUS` field in
the TASK block, so this dedicated block is how a stop is signalled.)

```
===AEGIS-STOP v1===
ITERATION: <n>
REASON: <objective-complete | budget-exhausted | abandoned | other:...>
===END-STOP===
```

On receiving this, the Executor sets `STATE.json.status = "STOPPED"`, appends a
final `HISTORY.md` row, and does nothing further until a new loop is started.

---

## 5. Courier model

The Courier is the transport layer, not an editor:

1. The Planner emits a `===AEGIS-TASK v1===` (or `===AEGIS-STOP v1===`) block.
2. The Courier pastes it **verbatim** to the Executor (mirrored into `INBOX.md`).
3. The Executor works and emits an `===AEGIS-REPORT v1===` block.
4. The Courier pastes it **verbatim** back to the Planner (mirrored into `OUTBOX.md`).
5. Repeat for iteration *n+1*.

Do not summarize, reword, or reorder sentinel content. The Courier **does** hold
approval authority: outward or irreversible actions (Rule 5) pause and wait for
the human's explicit yes/no.

---

## 6. Rules & guardrails

1. **One focused task per iteration** — no mega-tasks.
2. **Keep the suite green.** Every iteration MUST keep `python -m pytest`
   passing. If a change breaks tests, the Executor fixes it before reporting
   `STATUS: READY`, or reports `STATUS: BLOCKED`.
3. **Never weaken the authorization/scope guard.** `aegis/authorization.py` is
   the safety core. Weakening or bypassing it is **auto-rejected**.
4. **Forbidden feature classes** — the Executor **REFUSES** these, reports the
   refusal, and the loop continues with the next legitimate task:
   - denial-of-service / flooding;
   - destructive or persistence exploitation (reverse shells, malware,
     data deletion / defacement);
   - detection-evasion built for illicit concealment;
   - mass / indiscriminate targeting;
   - any real exploitation against systems **not** inside an authorized, signed
     test scope.
5. **Outward or irreversible actions require explicit human approval — with one
   standing exception.** Publishing, deleting data, third-party network calls,
   changing credentials/remotes, force-pushing, and anything else outward or
   irreversible are **AUTO-DENIED and logged** in autonomous mode — never
   auto-approved. The **standing exception**, granted explicitly by the human
   owner: `git push origin <current-branch>` (a plain, non-force push) to the
   `origin` remote **that was already configured before the loop started**.
   This is how autonomous mode keeps GitHub as a live, documented mirror of
   every iteration without a human relaying anything. The runner never creates
   a remote, never touches credentials, never force-pushes, and a failed push
   only logs a warning — it never blocks or corrupts local progress.
6. **The contract is immutable without human approval.** Any TASK that edits
   `loop/PROTOCOL.md`, the guardrails, the forbidden-feature list, or
   `aegis/authorization.py` is treated like Rule 5: it pauses for human sign-off.
   **In autonomous mode, an iteration whose diff touches any guarded path is
   reverted and logged as `AUTO-DENIED` — it never lands.** Guarded paths and
   their baseline hashes are pinned in `loop/.baselines.json`.
7. **Prefer additive, reversible work** — new modules, tests, docs, refactors.

---

## 7. Termination — how the loop stops (machine-enforced)

The loop is bounded so it **cannot run forever**. It halts on the **first** of:

1. **Planner ends it.** The Planner emits `===AEGIS-STOP v1===`.
2. **Iteration cap.** `STATE.json.max_iterations` (default **20**). Before
   executing a TASK, the Executor checks `iteration`. If it would exceed
   `max_iterations`, the Executor does **not** run the task; it reports
   `STATUS: BLOCKED` with `NOTES: iteration cap reached` and **pauses for the
   human** to either stop or raise the cap. The cap is enforced by the Executor,
   not left to good intentions.
3. **Stuck task.** Two `BLOCKED` reports on the **same `TASK_ID`**
   (`STATE.json.blocked_streak >= 2`). The Executor pauses for the human.

The Executor maintains `blocked_streak` in `STATE.json`: incremented on each
`BLOCKED` for the current `TASK_ID`, reset to 0 whenever the `TASK_ID` changes or
a `READY` is reported.

### 7.1 Autonomous health checkpoints (every 100 iterations)

In autonomous mode there is **no human in the per-iteration path**. Instead, the
runner performs a **full health analysis every `checkpoint_interval` iterations
(default 100)** and **gates continuation on the verdict**:

| Verdict | Meaning | Runner action |
|---------|---------|---------------|
| `HEALTHY` | Real, test-green progress; guardrails intact | auto-continue |
| `STALLING` | Progress flat (repeats, rising BLOCKED, no net tests/features) | **halt for review** |
| `DEGRADING` | Regressions, churn without value, shrinking coverage | **halt for review** |
| `BROKEN` | Suite red, or a guarded baseline changed | **halt immediately** |

Each checkpoint writes `loop/health/checkpoint-<n>.md` (metrics) and, when the
`claude` backend is available, `loop/health/checkpoint-<n>.analysis.md` (the
narrative verdict). The loop only keeps running while it is demonstrably
`HEALTHY`; anything else stops it and waits for a human. This is how "progressing
vs. degrading" is enforced mechanically rather than trusted.

---

## 8. Worked example — one full iteration

Illustrative; sentinel lines match [Section 4](#4-handshake--verbatim-sentinels)
exactly.

### 8.1 Planner emits the TASK (mirrored into `loop/INBOX.md`)

```
===AEGIS-TASK v1===
ITERATION: 3
TASK_ID: T-003
OBJECTIVE: Raise unit-test coverage of the assessment modules.
TASK: Add tests for aegis/modules/portscan.py covering the nmap-XML parser and the sensitive-port classification, using canned XML fixtures (no live network).
ACCEPTANCE: New tests pass; full suite stays green; no network calls in tests.
CONSTRAINTS: Additive only; do not modify portscan.py behavior.
===END-TASK===
```

### 8.2 Executor reports (mirrored into `loop/OUTBOX.md`)

```
===AEGIS-REPORT v1===
ITERATION: 3
TASK_ID: T-003
STATUS: READY
SUMMARY: Added tests/test_portscan.py with 5 cases: nmap XML parsing (open/closed/filtered), version extraction, and sensitive-port severity mapping. Used static XML fixtures; no sockets opened.
CHANGED_FILES: tests/test_portscan.py
TESTS: 15 passed
NOTES: _parse_nmap_xml handled malformed XML gracefully (returns []); added a case for it.
NEXT_INPUT_FOR_PLANNER: portscan is now covered. tls_check.py and web_headers.py still have no dedicated tests — good candidates for iteration 4.
===END-REPORT===
```

The Courier relays the REPORT back to the Planner, appends a `HISTORY.md` row,
and the Executor bumps `STATE.json` (`iteration: 3`, `status: "READY"`,
`last_task_id: "T-003"`, `blocked_streak: 0`, refreshed `last_updated`).
Iteration 4 planning begins from `NEXT_INPUT_FOR_PLANNER`.

---

## 9. Autonomous mode (no human in the loop)

When `STATE.json.mode == "autonomous"` the human Courier is removed from every
iteration. The two roles are re-bound to local, automatable sources:

| Role | Manual mode | Autonomous mode |
|------|-------------|-----------------|
| **Planner** | external AI | **`loop/BACKLOG.md`** — a curated, prioritized task list. Each iteration consumes the next unchecked `- [ ]` item. |
| **Executor** | Claude Code (chat) | **`claude -p` headless**, driven by `loop/runner.py`, doing exactly one backlog item per iteration. |
| **Courier** | the human | **`loop/runner.py`** — moves state, enforces guards, gates on health. |

### 9.1 What the runner does each iteration
1. Refuse to start on a dirty git tree (protects your uncommitted work).
2. Pull the next `- [ ]` item from `BACKLOG.md`. If none → **stop** (`backlog-empty`).
3. Reject the item if it matches a **forbidden feature class** (Section 6, Rule 4) → log `REFUSED`, continue.
4. Hand the item to the Executor backend to implement **additively**.
5. **Verify, don't trust:** run `python -m pytest`. If red, try one fix pass; if still red → `git reset --hard` + `git clean -fd` to the pre-iteration commit, mark `BLOCKED`.
6. **Guarded-path check:** if the diff touched any path in `.baselines.json` → revert, mark `AUTO-DENIED`.
7. On success: `git commit` the iteration, tick the backlog item, append `HISTORY.md`, bump `STATE.json`, then `git push origin <branch>` (the standing exception in Rule 5) so GitHub mirrors the change immediately. Every outcome — READY, BLOCKED, AUTO-DENIED, REFUSED, and every health checkpoint — is committed and pushed, so the remote history is a complete, documented audit trail of the whole run.
8. Every `checkpoint_interval` iterations → run the health analysis and **gate** (Section 7.1).

### 9.2 Stop conditions (autonomous)
The loop halts on the **first** of: backlog empty · `iteration >= max_iterations`
· health verdict ≠ `HEALTHY` at a checkpoint · `blocked_streak >= 2` on one item
· dirty-tree/precondition failure. Every stop is recorded in `STATE.json` and
`HISTORY.md`. Refilling `BACKLOG.md` and clearing the stop reason resumes it.

### 9.3 What stays true
The hard guardrails (Section 6) are unchanged. Removing the human does **not**
relax them — it converts "pause and ask" into "auto-deny and log", and adds the
automatic health brake. The **only** outward action the runner performs is the
standing-exception push in Rule 5 — a plain push of the current branch to the
pre-configured `origin`. It never force-pushes, never creates or deletes a
remote/repo, never touches credentials, and never calls any other external
service. The worst a bad iteration can do is fail tests and be reverted, then
that revert is committed and pushed too — so nothing is ever hidden.
