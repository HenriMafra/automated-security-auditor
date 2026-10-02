# AEGIS Prompt Loop

This directory drives the **AEGIS prompt-loop** — an autonomous, auditable
cycle that advances the `aegis-pentest` project one focused, test-verified
change at a time, **committing and pushing every outcome to GitHub as it
happens.** The remote repository is always the live, documented mirror of the
loop's state — nothing is batched or hidden.

## Two modes

### Autonomous (default — no human per iteration)

| Role | Implementation |
|------|----------------|
| **Planner** | `BACKLOG.md` — a curated, checkbox task list. Next `- [ ]` = next iteration. |
| **Executor** | `runner.py`, calling `claude -p` headless (or `--backend dry-run` for a no-op test of the pipeline). |
| **Courier** | `runner.py` itself — commits, pushes, and gates continuation. |

Run it:

```bash
python loop/health_report.py --init   # once, before the first run: pins guarded-path baselines
python loop/runner.py --backend claude --auto
```

Every iteration — `READY`, `BLOCKED`, `AUTO-DENIED`, or `REFUSED` — is
committed **and pushed** to `origin` immediately. Every `checkpoint_interval`
iterations (default 100) it also runs `health_report.py`, commits and pushes
`loop/health/checkpoint-<n>.md`, and **halts** unless the verdict is `HEALTHY`.
See `PROTOCOL.md` Section 9 for the exact rules, and Section 7.1 for how the
health gate works.

**The only outward action the runner ever performs is a plain `git push origin
<branch>` to the `origin` remote that was already configured before the loop
started.** No force-push, no new remote, no credential handling, no other
network call. Everything else outward or irreversible is auto-denied and
logged, per `PROTOCOL.md` Rule 5.

### Manual (optional — human-relayed, for a single external Planner AI)

If you'd rather drive one task at a time with an external chat AI as Planner
and yourself as Courier, use the sentinel handshake in `PROTOCOL.md` Section 4
directly: the Planner emits `===AEGIS-TASK v1===`, you relay it, the Executor
(Claude Code chat) replies `===AEGIS-REPORT v1===`, you relay that back. Use
`INBOX.md`/`OUTBOX.md` as the mirrors and `BOOTSTRAP.md` as the message that
starts it. This mode is not what runs by default — `runner.py` implements the
autonomous mode above.

## Files here

| File | What it holds |
|------|---------------|
| `PROTOCOL.md` | The full contract — both modes, guardrails, health gate, termination. **Read this first.** |
| `BACKLOG.md` | The autonomous Planner's task queue. Refill it to give the loop more work. |
| `runner.py` | The autonomous Executor/Courier — one iteration or `--auto` continuous. |
| `health_report.py` | The every-100-iterations health analysis (also runnable standalone). |
| `.baselines.json` | Pinned hashes of guarded paths (`aegis/authorization.py`, `PROTOCOL.md`, ...). |
| `health/checkpoint-*.md` | One report per checkpoint: metrics, verdict, recommendation. |
| `INBOX.md` / `OUTBOX.md` | Latest task/report mirror (both modes). |
| `HISTORY.md` | Append-only log of every iteration, in both modes. |
| `STATE.json` | Mode, iteration, iteration cap, checkpoint interval, status, streaks. |
| `BOOTSTRAP.md` | The message to send an external Planner AI (manual mode). |

## Safety, in one paragraph

Guarded paths can't be changed by an iteration (auto-reverted and logged).
Forbidden feature classes (DoS, destructive exploitation, evasion, mass
targeting, weakening the auth guard) are refused, not executed. A red test
suite reverts the iteration. Two `BLOCKED` reports on the same task, an empty
backlog, the iteration cap, or a non-`HEALTHY` checkpoint all stop the loop and
leave a documented reason in `STATE.json` and `HISTORY.md` — resuming is a
deliberate action (refill the backlog / clear the stop reason), never automatic.
