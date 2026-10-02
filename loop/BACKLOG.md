# BACKLOG — the autonomous Planner's task source

Each unchecked item below is **one iteration**. The runner consumes the top
unchecked `- [ ]` item, hands it to the Executor, and ticks it to `- [x]` when
the iteration lands green. When every item is checked, the loop stops with
`stop_reason: backlog-empty` — refill this file to give it more fuel.

**Rules for items** (so the loop stays healthy and on-rails):
- Additive and reversible. No changes to `aegis/authorization.py`, the guardrails,
  or `loop/PROTOCOL.md` (those are guarded — such iterations are auto-denied).
- Each item must be completable in one focused pass and keep `pytest` green.
- Nothing from the forbidden feature classes (DoS, destructive exploitation,
  evasion, mass-targeting) — those are refused.

Format: `- [ ] T-<nnn> (<area>): <concrete task with acceptance>`

---

## Priority 1 — test coverage (prove the engine behaves)

- [ ] T-001 (tests): Add `tests/test_portscan.py` covering `_parse_nmap_xml` (open/closed/filtered, malformed XML → []) and the sensitive-port severity mapping, using static XML fixtures. No sockets. Suite stays green.
- [ ] T-002 (tests): Add `tests/test_web_headers.py` covering missing-security-header detection and insecure-cookie-flag detection using a mocked `requests` response. No network.
- [ ] T-003 (tests): Add `tests/test_tls_check.py` covering certificate-expiry severity buckets (expired / <15d / ok) with a fake cert dict. No network.
- [ ] T-004 (tests): Add `tests/test_fingerprint.py` covering the header-leak and body-signature detection paths with canned responses.
- [ ] T-005 (tests): Add `tests/test_models.py` covering `Finding.key` dedup stability, `Severity.parse`, and `to_dict` round-trips.
- [ ] T-006 (tests): Add `tests/test_engine.py` covering `_normalize_host`, `_dedupe` ordering by severity, and that a module raising an exception does not abort the run (fail-safe).
- [ ] T-007 (tests): Add `tests/test_reporting.py` asserting `write_reports` emits findings.json/report.md/report.html and that severity counts are correct.
- [ ] T-008 (tests): Add `tests/test_catalog.py` asserting every `catalog_id` emitted by a module exists in `catalog/vulnerabilities.yaml`, and flag ids present in one but not the other.

## Priority 2 — CI & quality gates

- [ ] T-009 (ci): Add `.github/workflows/ci.yml` running `pip install -r requirements.txt`, `pytest`, and `ruff check` on push/PR (Python 3.10–3.12 matrix).
- [ ] T-010 (quality): Add a `ruff`/lint config pass and fix any lint findings without changing behavior.
- [ ] T-011 (tests): Add coverage measurement (`pytest --cov`) and a `make test` / `tox`-style entry; report the number, do not enforce a gate yet.

## Priority 3 — reporting & catalog hardening

- [ ] T-012 (report): Add a JSON Schema for `findings.json` and a test that validates real output against it.
- [ ] T-013 (report): Add redaction of obviously sensitive tokens (e.g. `Authorization:` header values, cookies) from `evidence.log`, with a test.
- [ ] T-014 (catalog): Reconcile the TLS ids — the module emits `AEG-TLS-000` (no catalog entry) and the catalog has `AEG-TLS-003` (no emitter). Either add the missing catalog entry for 000 and mark 003 as manual, or align them. Update `tests/test_catalog.py`.
- [ ] T-015 (docs): Generate `catalog/CATALOG.md` from `vulnerabilities.yaml` (a readable table of every check) via a small script + test.

## Priority 4 — safe, non-intrusive detection additions

- [ ] T-016 (module): Add a non-intrusive `robots_sitemap` module that fetches `/robots.txt` and `/sitemap.xml` and records disclosed paths as INFO findings, with tests using canned responses. Register it in the engine and catalog.
- [ ] T-017 (module): Add a `dns_email_posture` extension that also checks DMARC/DKIM presence (INFO/LOW), with tests. Additive to `recon`, no new intrusive behavior.
- [ ] T-018 (module): Add a `cors_headers` passive check (reports `Access-Control-Allow-Origin: *` with credentials as a finding), tests with canned responses.

## Priority 5 — developer experience

- [ ] T-019 (docs): Expand `README.md` "Extending Aegis" with a copy-paste module skeleton that matches `SPEC.md` section 12.
- [ ] T-020 (dx): Add a `CONTRIBUTING.md` describing the module contract, test conventions, and the non-destructive policy.
