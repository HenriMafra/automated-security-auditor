# Aegis — Authorized Security Assessment Framework · Specification

Aegis is a black-box, external security-assessment framework for **authorized** engagements only. It performs auditable, scope-gated, non-destructive reconnaissance and posture checks against targets that a signed, time-boxed authorization document explicitly permits. A cryptographic `ScopeGuard` gates every target and every activity level before any module touches the network; a fixed pipeline of six modules (recon, port scan, TLS check, fingerprint, web-header hygiene, and an opt-in intrusive Nuclei pass) produces `Finding` objects that are deduplicated, severity-sorted, mapped to a static vulnerability catalog, and rendered to JSON, Markdown, and self-contained HTML alongside a full JSONL evidence log. The framework is deliberately conservative: it has no scope-override flag, disallows destructive/DoS/mass-targeting behavior by design, degrades gracefully when optional tools or Python packages are absent, and is fail-safe (one module raising never aborts a run).

---

## 1. Design principles & security boundaries

Aegis's guiding philosophy, enforced (not merely advised) in code:

- **Authorized-only.** Nothing touches a target unless the authorization is valid, in-window, and the target is in scope. The authorization is a signed, time-boxed document bound to a scope by SHA-256 hash and optionally by HMAC. **There is no override flag** — the only sanctioned way to test something new is to change the scope and re-sign it.
- **Fail-safe, not fail-stop.** A module that raises is caught, logged, and skipped; the run continues. Missing optional tooling is a clean skip, not a crash.
- **Non-destructive by contract.** No destructive actions, DoS, data modification, or persistence — ever. Probes are read-only GETs / connect scans / handshakes / DNS lookups.
- **Scope-gated at two axes.** Every target passes `target_reason()`; every activity passes `check_activity(active, intrusive)`. Both must pass.
- **Two-key interlock for intrusion.** Intrusive modules require **both** scope `allow_intrusive: true` **and** the per-run `--enable-intrusive` flag.
- **Polite.** All framework HTTP is throttled through a shared rate limiter capped at the scope's `max_rps`.
- **Auditable.** Every sanctioned HTTP request is appended to `evidence.log` (JSONL) for the client's audit trail. Reports carry the scope hash and engagement metadata.
- **Report and continue, never crash.** `validate()` reports problems as a list of strings; only `assert_valid()` raises.

**Explicitly out of scope / forbidden by design:** denial-of-service or resource exhaustion; destruction, modification, or persistence of data; detection-evasion / stealth tradecraft; mass or untargeted scanning. The rate limiter, the connect-scan timeout caps, the read-only probe set, the fixed target list, and the identifying default User-Agent (`Aegis/0.1 (+authorized-assessment)`) all embody these boundaries. The license carries a Responsible-Use Notice restricting the software to lawfully authorized assessments.

---

## 2. Repository layout

```
aegis-pentest/
├── aegis/                       # The Python package
│   ├── __init__.py              # Exposes __version__ (rendered by `aegis --version`)
│   ├── models.py                # Core data models: Severity, Confidence, Finding, Service, Target
│   ├── config.py                # RunConfig, DEFAULT_PORTS, load_catalog(), catalog_entry()
│   ├── utils.py                 # log/info/good/warn/err, RateLimiter, have_tool, resolve_host, is_ip, ip_in_networks, host_matches, Timer
│   ├── authorization.py         # Scope, Authorization, ScopeGuard, AuthorizationError (the safety core)
│   ├── engine.py                # ScanContext, Engine — orchestration, gating, fail-safe, dedupe/sort
│   ├── cli.py                   # `aegis verify | run | catalog`, main(), exit-code contract
│   ├── reporting.py             # write_reports() → findings.json, report.md, report.html
│   └── modules/
│       ├── __init__.py
│       ├── base.py              # Module ABC (name/phase/active/intrusive, available(), run())
│       ├── recon.py             # ReconModule — DNS / reverse-DNS / SPF posture
│       ├── portscan.py          # PortScanModule — nmap or native TCP connect scan
│       ├── tls_check.py         # TlsModule — cert expiry + legacy-protocol detection
│       ├── fingerprint.py       # FingerprintModule — header/body tech fingerprinting
│       ├── web_headers.py       # WebHeadersModule — security headers, cookie flags, sensitive paths
│       └── nuclei.py            # NucleiModule — opt-in intrusive template scan (external nuclei)
├── catalog/
│   ├── vulnerabilities.yaml     # The vulnerability catalog (check ids, severity, module routing)
│   └── methodology.md           # Prose black-box methodology (phases, safety rules, deliverables)
├── config/
│   ├── scope.example.yaml       # Scope / rules-of-engagement template (copy → scope.yaml)
│   ├── authorization.example.yaml  # Authorization document template (copy → authorization.yaml)
│   ├── scope.yaml               # Filled-in engagement scope (git-ignored)
│   └── authorization.yaml       # Filled-in engagement authorization (git-ignored)
├── tests/
│   └── test_authorization.py    # Behavioral spec for the scope/authorization guard
├── reports/
│   ├── .gitkeep                 # Keeps the dir; every reports/<timestamp>/ run output is git-ignored
│   └── <UTCstamp>/              # Per-run artifacts: findings.json, report.md, report.html, evidence.log
├── README.md
├── pyproject.toml               # PEP 517/518 setuptools build; deps; `aegis` console entry point
├── requirements.txt             # Runtime deps (mirrors pyproject; no dev extras)
├── LICENSE                      # MIT + Responsible-Use Notice
└── .gitignore                   # Ignores real config/*.yaml, reports/*/, *.log, caches
```

Dependency direction inside the package: `models.py`, `config.py`, `utils.py` form the leaf layer (they do not import each other). `authorization.py` imports `utils`. `engine.py` wires `authorization`, `config`, `models`, `utils`, and the six modules. `modules/base.py` imports `ScanContext` only under `TYPE_CHECKING` to avoid an engine↔base import cycle. `cli.py` and `reporting.py` sit at the top.

---

## 3. Dependencies

### Required Python packages (`pyproject.toml [project].dependencies`, mirrored in `requirements.txt`)

| Package | Floor | Used for |
|---|---|---|
| `PyYAML` | `>=6.0` | Parsing `scope.yaml`, `authorization.yaml`, and `catalog/*.yaml`. **Hard import** in `config.py` and `authorization.py` — absence breaks those modules at import time. |
| `requests` | `>=2.31` | HTTP probes (fingerprint, web headers). `ScanContext.session`/`request`. |
| `dnspython` | `>=2.4` | DNS / reverse-DNS recon (`recon.py`). **Optional at runtime** — imported under `try/except`; see graceful degradation below. |
| `rich` | `>=13.7` | Styled terminal output (`utils.py`). **Optional at runtime** — falls back to plain `print`. |
| `jinja2` | `>=3.1` | HTML report templating (`reporting.py`). **Optional at runtime** — falls back to `<pre>`-wrapped Markdown. |

Dev extras (`[project.optional-dependencies].dev`): `pytest>=8.0`, `ruff>=0.5`. Required to run the test suite. `requirements.txt` lists only the five runtime deps (no dev extras); the two dependency sources must be kept in sync manually.

Build: `setuptools>=68`, `setuptools.build_meta`. `requires-python = ">=3.10"`. Console entry point: `aegis = "aegis.cli:main"`. Package data bundles `../catalog/*.yaml` and `../catalog/*.md` (a parent-relative glob that may be fragile across build backends). Ruff: `line-length = 100`, `target-version = "py310"`.

### Optional external tools (detected via `utils.have_tool` = `shutil.which`, no execution to probe)

| Tool | Module | Behavior when present | Graceful degradation when absent |
|---|---|---|---|
| **nmap** | `portscan` | `nmap -Pn -sT -sV --version-light -p <ports> -oX - <host>` → parsed XML with product/version. | Warns and falls back to a native Python TCP connect scan (`socket.create_connection`), which honors the rate limiter and yields ports without product/version. |
| **nuclei** | `nuclei` | Runs template scan; `available()` returns `(True, "")`. | `available()` returns `(False, "nuclei binary not found on PATH")`; the engine logs a warning and **skips** the module cleanly (no crash). |

Runtime package degradation:
- **rich absent** → `utils.log`/`info`/`good`/`warn`/`err` fall back to plain `print`, ignoring style.
- **dnspython absent** (`_HAVE_DNS = False`) → `recon` falls back to `records["A"] = target.resolved_ips` (populated by the engine) and skips full record enumeration.
- **jinja2 absent** → `reporting._html` returns `"<pre>" + _markdown(...) + "</pre>"`; HTML generation never hard-fails.

---

## 4. Data models (`aegis/models.py`)

Module uses `from __future__ import annotations`; all dataclasses use `slots=True` (no `__dict__`; undeclared attributes cannot be set).

### `Severity(enum.IntEnum)` — ordered (higher = worse)

`INFO=0`, `LOW=1`, `MEDIUM=2`, `HIGH=3`, `CRITICAL=4`. Subclasses `IntEnum` so findings sort/compare numerically.

- **`classmethod parse(value: str | int | Severity) -> Severity`** — returns a `Severity` unchanged; for `int` uses `cls(value)` (by value, `ValueError` out of 0–4); otherwise `cls[str(value).strip().upper()]` (by **name**, after strip+upper). Gotchas: the numeric string `"3"` goes through the name path → `KeyError` (not `HIGH`); pass a real `int` for value lookup. Because `bool` subclasses `int`, `parse(True)` → `LOW` (unintended edge).
- **`label() -> str`** — `self.name.capitalize()` (e.g. `"Critical"`). Used in serialized/human output.

### `Confidence(enum.Enum)` — unordered, string-valued

`TENTATIVE="tentative"`, `FIRM="firm"`, `CONFIRMED="confirmed"`. `.value` is used directly during serialization. (Reporting-only dimension; **not** present in the catalog schema.)

### `@dataclass(slots=True) Finding` — "a single observation produced by a module"

| Field | Type | Default | Notes |
|---|---|---|---|
| `title` | `str` | (required) | |
| `severity` | `Severity` | (required) | |
| `module` | `str` | (required) | Producing module's name. |
| `target` | `str` | (required) | The asset (a string, not a `Target`). |
| `category` | `str` | `"misc"` | |
| `catalog_id` | `str \| None` | `None` | Join key into the catalog `_index`. |
| `description` | `str` | `""` | |
| `evidence` | `str` | `""` | |
| `remediation` | `str` | `""` | |
| `confidence` | `Confidence` | `Confidence.FIRM` | |
| `references` | `list[str]` | `[]` (factory) | |
| `cvss` | `float \| None` | `None` | |
| `discovered_at` | `str` | ISO-8601 UTC now (per-instance factory) | Wall-clock read at construction; stored as string. |

- **`property key -> str`** — `sha256(f"{category}|{title}|{target}".lower())[:16]` (16 hex chars = 64-bit, recomputed each access). **Dedup identity = category + title + target only, case-insensitive.** It does **not** include `module`, `severity`, `evidence`, or `catalog_id`; two findings differing only in module/severity collapse to the same key. Treat as a dedup key, not a cryptographic id.
- **`to_dict() -> dict`** — `dataclasses.asdict(self)` with `severity` → `label()`, `confidence` → `.value`, plus added `key`. Canonical JSON-friendly shape for reporters/exporters.

### `@dataclass(slots=True) Service` — a discovered network service

`port:int` (required), `protocol="tcp"`, `state="open"`, `service=""`, `product=""`, `version=""`. `to_dict()` returns `dataclasses.asdict` verbatim.

### `@dataclass(slots=True) Target` — the mutable accumulator modules enrich

`host:str` (required), `ip:str|None=None`, `resolved_ips:list[str]=[]`, `services:list[Service]=[]`, `urls:list[str]=[]`, `metadata:dict[str,Any]={}`.

- **`base_url(prefer_https=True) -> str`** — `f"{scheme}://{host}"` from **host only**; ignores `ip`, ports, and does no validation (malformed if host already has scheme/port).
- **`to_dict() -> dict`** — manually built (not `asdict`) so it can recurse `services` via `[s.to_dict() ...]`; other fields (`resolved_ips`, `urls`, `metadata`) are copied **by reference** — mutating them later mutates the returned dict.

---

## 5. Configuration & the vulnerability catalog

### 5.1 `RunConfig` and constants (`aegis/config.py`)

Module constants (resolved at import):
- `PROJECT_ROOT = Path(__file__).resolve().parent.parent` — repo root (parent of the `aegis/` package).
- `CATALOG_PATH = PROJECT_ROOT / "catalog" / "vulnerabilities.yaml"`.
- `DEFAULT_PORTS` — a fixed 41-port TCP list used by the native scanner when no ports are configured: `21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5601, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9300, 11211, 27017` (SSH/HTTP/DB/RPC/Docker 2375/Redis 6379/Elasticsearch 9200/Mongo 27017/…). Module-level mutable list — do not mutate in place.

**`@dataclass(slots=True) RunConfig`** — "everything a run needs beyond the scope guard":

| Field | Type | Default | Meaning |
|---|---|---|---|
| `targets` | `list[str]` | (required) | |
| `out_dir` | `Path` | (required) | Run artifact directory (not created here). |
| `timeout` | `float` | `10.0` | Per-operation timeout (s). |
| `threads` | `int` | `8` | Concurrency hint. |
| `user_agent` | `str` | `"Aegis/0.1 (+authorized-assessment)"` | Default HTTP UA. |
| `ports` | `list[int]` | `[]` | Empty = sentinel for `DEFAULT_PORTS` (wiring in the scanner). |
| `modules` | `list[str] \| None` | `None` | `None` = all default modules. |
| `enable_intrusive` | `bool` | `False` | Per-run intrusive gate (safe default off). |

Scope/authorization enforcement lives in the `ScopeGuard`, **not** here.

### 5.2 Catalog access

- **`load_catalog() -> dict`** (`@lru_cache(maxsize=1)`): reads and parses `CATALOG_PATH` **once per process** (mutable shared cache — treat as read-only; `load_catalog.cache_clear()` forces reload). If the file is missing → `{"categories": [], "_index": {}}` (no exception). Otherwise `yaml.safe_load(... ) or {}`, then builds `_index`: for each category → each check with a truthy `id`, stores a shallow copy enriched with `category` (parent `name`, default `"misc"`) and `owasp` (parent `owasp`, default `""`). Checks without an `id` are skipped; duplicate ids across categories → last wins. Propagates `yaml.YAMLError` / OS read errors (not cached, since `lru_cache` doesn't cache exceptions). `.get(...)` used defensively, but a non-list `categories` or non-dict `check` raises `TypeError`/`AttributeError`.
- **`catalog_entry(catalog_id) -> dict | None`**: `load_catalog().get("_index", {}).get(catalog_id)` — the enriched check dict or `None`. This ties `Finding.catalog_id` back to catalog metadata. **Note:** no assessment module actually calls this; it exists for the reporting/correlation stage.

### 5.3 Catalog file format (`catalog/vulnerabilities.yaml`)

Static data, no logic. Top level: `version` (int, currently `1`) and `categories` (list).

**`category` object:** `name` (str), `owasp` (free-form label — **not** always an OWASP code; observed values include `PTES-Intel`, `NIST-800-115`, `A02:2021-Cryptographic-Failures`, `API:2023`, `Anti-Spoofing`; treat as free-form, not parseable), `checks` (list). The 17 categories, in file order: Reconnaissance & OSINT; Attack surface & network; Transport security (TLS/SSL); A01 Broken Access Control; A02 Cryptographic Failures; A03 Injection; A04 Insecure Design; A05 Security Misconfiguration; A06 Vulnerable & Outdated Components; A07 Identification & Authentication Failures; A08 Software & Data Integrity Failures; A09 Security Logging & Monitoring Failures; A10 SSRF; API security; Email security.

**`check` object — every field of a catalog entry:**

| Field | Type | Contract |
|---|---|---|
| `id` | str | **Stable Aegis identifier — findings reference this** (the join key to `catalog_entry`). |
| `title` | str | Short name. |
| `severity` | enum str | One of `info \| low \| medium \| high \| critical` (same scale as `models.Severity`). |
| `automated` | bool | `true` = an Aegis module tests it today; `false` = methodology-only, manual. |
| `module` | str | Covering module name, or the literal `"manual"`. |
| `techniques` | list[str] | Black-box techniques (free-form; no closed vocabulary). |
| `detection` | str | What indicates the issue. |
| `remediation` | str | The fix. |
| `references` | list[str] | Authoritative URLs. |

**Enumerated ids present:** Recon `AEG-RECON-001/002/003`; Net `AEG-NET-001/002/003`; TLS `AEG-TLS-001/002/003`; A01 `AEG-AC-001/002/003`; A02 `AEG-CR-001/002`; A03 `AEG-INJ-001..005`; A04 `AEG-DES-001/002`; A05 `AEG-HDR-001/002`, `AEG-INFO-002`, `AEG-CFG-001/002/003`; A06 `AEG-FP-001`, `AEG-INFO-001`, `AEG-NUCLEI`; A07 `AEG-AUTH-001/002/003`; A08 `AEG-INT-001/002`; A09 `AEG-LOG-001`; A10 `AEG-SSRF-001`; API `AEG-API-001/002/003`; Email `AEG-EMAIL-001/002`.

**Id gotchas (ground truth):** the scheme is **not** strictly `AEG-<CATEGORY>-<NNN>` — `AEG-NUCLEI` has no numeric suffix; ids are **not** grouped purely by prefix — `AEG-INFO-002` lives in A05 while `AEG-INFO-001` lives in A06, and `-002` appears before `-001` in the file. Do not infer category from prefix or assume numeric ordering. `AEG-AUTH-003` techniques contain a verbatim typo token `logout-invalidce`.

**Module routing map (automation source of truth):**

| `module` | Checks | `automated` |
|---|---|---|
| `recon` | `AEG-RECON-001`, `AEG-EMAIL-001` | true |
| `portscan` | `AEG-NET-001`, `AEG-NET-002` | true |
| `tls_check` | `AEG-TLS-001`, `AEG-TLS-002` | true |
| `web_headers` | `AEG-HDR-001`, `AEG-HDR-002`, `AEG-INFO-002` | true |
| `fingerprint` | `AEG-FP-001`, `AEG-INFO-001` | true |
| `nuclei` | `AEG-NUCLEI` | true |
| `manual` | all remaining (majority) | false |

**Invariant:** `module: manual` ⇔ `automated: false`; a real module name ⇔ `automated: true`. **Cross-file gotcha:** SPF (`AEG-EMAIL-001`) is automated and folded into `recon`, not a dedicated email module; DMARC/DKIM (`AEG-EMAIL-002`) is manual.

### 5.4 How findings link to catalog ids

A module hard-codes a free-form `catalog_id` string on each `Finding` (e.g. `AEG-RECON-001`). No module looks the id up. The correlation/reporting stage is the intended consumer of `config.catalog_entry(catalog_id)` to attach category, OWASP tag, remediation, and references. Severity is expressed on the shared `info…critical` scale in both the catalog and findings.

### 5.5 Methodology (`catalog/methodology.md`)

Prose spec declaring Aegis a black-box external assessment aligned to OWASP WSTG, OWASP Top 10 (2021), OWASP API Security Top 10 (2023), PTES, and NIST SP 800-115. Phases map directly onto module names: (0) pre-engagement/authorization out-of-band, scope hashed into the authorization; (1) `recon`; (2) `portscan`+`tls_check`+`fingerprint`; (3) `web_headers`; (4) `nuclei` + manual; (5) correlation/scoring/reporting (dedupe, severity-score, map to catalog ids). It restates the five enforced safety rules (scope gate with no override; rate-limit to `max_rps`; intrusive two-key interlock; no destructive/DoS/persistence; every request logged) and names the deliverables (`report.html`, `report.md`, `findings.json`, `evidence.log`).

---

## 6. Authorization & scope model (safety core, `aegis/authorization.py`)

Module docstring: "Nothing touches a target unless this module says the engagement is authorized, in-window, and the target is in scope." **No override flag by design** — re-sign to change what is tested. Uses `hashlib`, `hmac`, `json`, `datetime`, `yaml`, and delegates all host/IP/CIDR matching to `aegis/utils.py`. `AuthorizationError(Exception)` is the sole custom exception.

### 6.1 `@dataclass(slots=True) Scope` — "rules of engagement: what may be touched and how hard"

| Field | Type | Default | Meaning |
|---|---|---|---|
| `in_scope` | `list[str]` | `[]` | Authorized hosts / wildcards / IPs / CIDRs. |
| `out_of_scope` | `list[str]` | `[]` | Exclusions; **win over `in_scope`**. |
| `allowed_ports` | `list[int]` | `[]` | Empty = "default top ports" (enforced in the scanner, not here). |
| `max_rps` | `float` | `5.0` | Rate cap (enforced by the engine's `RateLimiter`, not here). |
| `allow_active` | `bool` | `True` | Whether active probing is permitted. |
| `allow_intrusive` | `bool` | `False` | Whether intrusive probing is permitted. |

- **`from_dict(data)`** — coerces each field (`str`/`int`/`float`/`bool`), all keys optional via `.get`. Gotcha: `bool("false")` is `True`, but normal YAML booleans parse correctly through `yaml.safe_load`; non-numeric `max_rps`/ports raise `ValueError`.
- **`canonical_bytes() -> bytes`** — deterministic JSON with `in_scope`/`out_of_scope`/`allowed_ports` **sorted**, plus the three scalars, `json.dumps(sort_keys=True, separators=(",",":")).encode()`. Sorting makes hashing **order-independent**. A `max_rps` type change (`5.0` vs `5`) changes the JSON and thus the hash.
- **`hash() -> str`** — `sha256(canonical_bytes()).hexdigest()` (64 hex). Must equal `Authorization.scope_hash`.

### 6.2 `@dataclass(slots=True) Authorization` — "a signed, time-boxed authorization document"

Fields: `client:str`, `authorized_by:str`, `contact:str`, `valid_from:datetime`, `valid_until:datetime`, `scope_hash:str` (all required, positional), `signature:str=""` (HMAC over `scope_hash|valid_from|valid_until`), `engagement_id:str=""`.

- **`from_dict(data)`** — `client`, `authorized_by`, `valid_from`, `valid_until` required (`KeyError`/`ValueError` if absent/bad); dates via `_parse_dt`; `contact`/`scope_hash`/`signature`/`engagement_id` optional (`.get(..., "")`, `str`-coerced).
- **`signing_payload() -> bytes`** — `f"{scope_hash}|{valid_from.isoformat()}|{valid_until.isoformat()}".encode()`. Signatures must be generated with the exact same isoformat representation (offset `+00:00` vs `Z` differences change the payload).
- **`expected_signature(key) -> str`** — `hmac.new(key.encode(), signing_payload(), sha256).hexdigest()`.

**`_parse_dt(value)`** (module helper): passes a `datetime` through; else `datetime.fromisoformat(str(value).replace("Z","+00:00"))`; a naive result is assumed UTC. `Z` replacement is a naive substring swap (only matters for the trailing zone in ISO timestamps). Malformed strings raise `ValueError`.

### 6.3 `@dataclass(slots=True) ScopeGuard` — the primary gate

Fields: `authorization`, `scope`, `signing_key: str | None = None` (if set, HMAC signature is enforced during `validate`; if `None`, signature checking is skipped entirely — the scope-hash check is then the only integrity guarantee).

- **`classmethod load(auth_path, scope_path, signing_key=None)`** — reads both files (`read_text(encoding="utf-8")`, `yaml.safe_load(... ) or {}`), builds sub-objects via `from_dict`, returns the guard. Raises `FileNotFoundError`/`OSError`/`yaml.YAMLError`/`KeyError`/`ValueError` as appropriate. **Does not validate** — call `validate()`/`assert_valid()` separately.

- **`validate() -> list[str]`** — engagement-level checks; **empty list = valid** (never raises). In order:
  1. **Non-empty scope:** `in_scope` empty → `"scope.in_scope is empty — nothing is authorized"`.
  2. **Scope-hash tamper check:** `actual = scope.hash()`; empty `scope_hash` → `"authorization has no scope_hash"`; else `hmac.compare_digest(auth.scope_hash, actual)` (constant-time) — mismatch → message noting `scope.yaml was modified after signing` with 12-char hash prefixes.
  3. **Time window:** `now = datetime.now(timezone.utc)`; `now < valid_from` → "engagement not yet valid (starts …)"; `now > valid_until` → "authorization expired (…)".
  4. **Optional signature:** only if `signing_key` truthy — empty `signature` → "signing key provided but authorization is unsigned"; else `hmac.compare_digest(signature, expected)` mismatch → "authorization signature is invalid".
  Uses constant-time comparison for both hash and signature.

- **`assert_valid() -> None`** — raises `AuthorizationError("Engagement is NOT authorized:\n  - " + …)` if `validate()` is non-empty; else returns. Fail-closed entry point.

- **`target_reason(host) -> str | None`** — per-target gate; returns a reason if **not** allowed, `None` if allowed. First match wins:
  1. **Out-of-scope (hostname/wildcard) wins first:** any `utils.host_matches(host, pat)` in `out_of_scope` → `"'{host}' is explicitly out of scope ({pat})"`.
  2. **Direct in-scope match:** any `utils.host_matches(host, pat)` in `in_scope` → `None`.
  3. **IP / CIDR match:** `candidates = [host] if utils.is_ip(host) else utils.resolve_host(host)` (**DNS side effect** for non-IP hosts). `cidr_scope` = in-scope entries that are IPs or contain `/`. For each candidate IP in an in-scope CIDR, re-check out-of-scope CIDRs (`oob_cidrs`): in one → `"'{host}' resolves to out-of-scope IP {ip}"`; else `None`.
  4. Fallthrough → `"'{host}' is not covered by any in_scope entry"`.
  Gotchas: out-of-scope is checked twice by different mechanisms (hostname/wildcard up front; CIDR only after an in-scope CIDR hit) — a CIDR out-of-scope entry is only enforced for resolved IPs that first matched an in-scope CIDR; DNS resolution can fire for untrusted/typo'd hosts.

- **`is_authorized(host) -> bool`** — `target_reason(host) is None` (same DNS side effect).

- **`check_activity(active, intrusive) -> str | None`** — `active and not allow_active` → `"active probing is disabled in scope (allow_active: false)"`; `intrusive and not allow_intrusive` → `"intrusive probing is disabled in scope (allow_intrusive: false)"`; else `None`. Pure; independent of target scoping — callers must combine it with `target_reason`.

### 6.4 Config templates that feed the guard

**`config/scope.example.yaml`** (copy → `scope.yaml`; its canonical SHA-256 is bound into `authorization.yaml.scope_hash`). Fields: `in_scope` (exact host / `*.example.com` wildcard / IP / CIDR), `out_of_scope` (exclusions win), `allowed_ports` (`[]` = default top ports, not "no ports"), `max_rps` (default `5`), `allow_active` (default `true`), `allow_intrusive` (default `false`).

**`config/authorization.example.yaml`** (copy → `authorization.yaml`; Aegis refuses to run if missing, expired, or hash-mismatched). Fields: `client`, `authorized_by`, `contact`, `engagement_id`, `valid_from`/`valid_until` (ISO-8601, UTC assumed if no offset), `scope_hash` (ships as placeholder `REPLACE_WITH_OUTPUT_OF_aegis_verify` — an un-edited copy fails verification by design), `signature` (optional HMAC-SHA256 over `scope_hash|valid_from|valid_until`, empty = skip, enforced only with `--signing-key`).

**Integrity chain:** scope content → canonicalized → SHA-256 → `authorization.scope_hash` → optionally HMAC'd with the validity window into `signature`. At run time: (a) time within `[valid_from, valid_until]`; (b) recomputed scope hash matches; (c) `--signing-key` → signature verified; (d) each target gated against in/out-of-scope; (e) `max_rps` applied by the engine; (f) intrusive requires `allow_intrusive` + `--enable-intrusive`.

---

## 7. Orchestration engine & module contract (`aegis/engine.py`, `aegis/modules/base.py`)

Design goals (docstring): fail-safe (one module raising never aborts), auditable (every HTTP request logged), polite (all network I/O through a shared rate limiter).

### 7.1 `@dataclass ScanContext` — shared mutable per-run state

Fields: `guard: ScopeGuard`, `config: RunConfig`, `session: requests.Session`, `rate: utils.RateLimiter`, `evidence_path: Path`, `findings: list[Finding] = field(default_factory=list)`. The engine `extend`s `findings` with each module's return value, so findings accumulate across all modules and targets in one run.

- **`request(method, url, **kwargs) -> requests.Response | None`** — the sanctioned HTTP entry point. Calls `rate.acquire()` first (throttle); `setdefault` `timeout=config.timeout`, `allow_redirects=True`, **`verify=False`** (TLS verification disabled — targets may be self-signed; override with `verify=True`); pops `headers` and `setdefault`s `User-Agent=config.user_agent`; issues `session.request`; logs to `evidence.log` on success, logs the error and returns `None` on `requests.RequestException`. Only `RequestException` is caught — other exceptions propagate. Callers must handle a `None` response.
- **`_log_evidence(method, url, status=None, error="")`** — appends one JSONL record `{ts, method, url, status, error}` (UTC ISO-8601) to `evidence_path` (append mode, open/close per call). **Not concurrency-safe**; the framework drives modules sequentially so it is never raced as written.

### 7.2 `class Engine`

- **`__init__(guard, config)`** — stores both; no side effects.
- **`_select_modules() -> list[Module]`** — lazily imports the six classes (import errors in optional modules surface here, not at engine import). **Fixed registry order = execution order per target:** `ReconModule, PortScanModule, TlsModule, FingerprintModule, WebHeadersModule, NucleiModule`. If `config.modules` is truthy, filters to modules whose `.name` is in that collection (a name matching nothing silently yields nothing — no error).
- **`run() -> list[Finding]`** — the main entry point:
  1. `guard.assert_valid()` — aborts before any I/O if it raises (propagates to caller).
  2. `out_dir.mkdir(parents=True, exist_ok=True)`; **truncates** `out_dir/"evidence.log"` via `write_text("")` — each run starts a fresh log.
  3. Creates a `requests.Session`.
  4. Best-effort suppression of urllib3 `InsecureRequestWarning` (wrapped in `try/except`, non-fatal) — pairs with the `verify=False` default.
  5. Builds `RateLimiter(guard.scope.max_rps)` — the rate ceiling comes from the **signed scope**, not `config`.
  6. Constructs `ScanContext` (empty findings).
  7. `_select_modules()`, logs count and names.
  8. For each `raw_host` in `config.targets`: `_normalize_host`; `reason = guard.target_reason(host)` → if truthy, `warn("SKIP …")` and `continue`; else `good(...)`, build `Target(host=host)`, resolve `ips = utils.resolve_host(host)`, set `resolved_ips` and `ip = ips[0] if ips else None`, run each selected module via `_run_one`.
  9. Logs completion with the **pre-dedupe** count (`len(ctx.findings)`, can exceed the returned count), returns `_dedupe(ctx.findings)`.
- **`_run_one(module, target, ctx) -> None`** — gating in order, each logging and returning early:
  1. `activity_reason = ctx.guard.check_activity(module.active, module.intrusive)` → if truthy, `warn("skipped: …")`.
  2. `module.intrusive and not ctx.config.enable_intrusive` → "intrusive not enabled for this run". (So intrusive needs **both** scope authorization **and** the per-run flag.)
  3. `ok, why = module.available()` → if not `ok`, "unavailable: {why} (continuing)".
  Then times `module.run(target, ctx)` with `time.monotonic()`, `extend`s `ctx.findings`, logs count and elapsed (`{elapsed:0.1f}s`). **Fail-safe:** wrapped in `try/except Exception` — any exception is `err("error: {exc!r} (skipped)")` and swallowed; the run continues. Catches `Exception` (not `BaseException`), so `KeyboardInterrupt`/`SystemExit` still propagate.

### 7.3 Module-level helpers

- **`_normalize_host(raw) -> str`** — `strip()`, strip a single leading `https://`/`http://`, take before first `/`, before first `:`, then `rstrip(".")`. Handles common hostname/URL cases; mishandles bracketed IPv6 literals.
- **`_dedupe(findings) -> list[Finding]`** — dict keyed by `f.key`, `setdefault` keeps the **first** occurrence; sorts survivors by `(int(f.severity), f.category)`, `reverse=True` — **highest severity first**, ties broken by `category` reverse-lexicographic.

### 7.4 `class Module(abc.ABC)` — the contract every module implements

Class attributes (overridable defaults): `name="base"` (unique CLI/report id, used by `_select_modules`), `phase="misc"` (human label; not used for engine ordering), `active=True` (sends traffic; passed to `check_activity`), `intrusive=False` (noisy probes; gated by `check_activity` **and** `config.enable_intrusive`).

- **`available() -> tuple[bool, str]`** — default `(True, "")`; override to report missing tooling (a `(False, reason)` is a skip, not a failure).
- **`run(target, ctx) -> list[Finding]`** (`@abstractmethod`) — perform the work, return findings. Implementations **should** use `ctx.request(...)` (which wraps `rate.acquire()` + evidence logging); using `ctx.session` directly bypasses the audit log. `ScanContext` is imported only under `TYPE_CHECKING` (string annotation) to avoid an import cycle. The engine invokes `run` inside its fail-safe wrapper.

---

## 8. Module reference

All six subclass `Module`, are instantiated once by the engine, and are gated by `check_activity`/`enable_intrusive`/`available` before `run`. Exceptions raised inside `run` never propagate — they are caught, logged by `utils.err`, and the run continues. Network-level modules (`recon`, `portscan`, `tls_check`) and the subprocess module (`nuclei`) do their own I/O and therefore **bypass `evidence.log`** (though `portscan._native` still honors `ctx.rate`); only `fingerprint` and `web_headers` use `ctx.request` and are logged.

### 8.1 `recon` — `ReconModule`

- **Flags:** `name="recon"`, `phase="recon"`, `active=True`, `intrusive=False`.
- **Catalog ids / findings:** `AEG-RECON-001` (unconditional INFO "DNS reconnaissance", evidence e.g. `Records: A=2, MX=1. PTR: {…}`); `AEG-EMAIL-001` (conditional LOW "No SPF record found", category "Email security", RFC 7208) when `v=spf1` is absent (case-insensitive) from the joined TXT records — **also fires when there are no TXT records at all**.
- **External tool + fallback:** optional **dnspython**. `_HAVE_DNS=True` → `dns.resolver.Resolver()` with `lifetime=config.timeout` (per-query `timeout` not set), enumerates `RECORD_TYPES = [A, AAAA, MX, NS, TXT, CNAME, SOA]` (per-type failures swallowed). Absent → `records["A"] = target.resolved_ips` (only if non-empty). Reverse DNS via `socket.gethostbyaddr(ip)[0]` per resolved IP (failures swallowed). Writes `target.metadata["dns"]` and optionally `["ptr"]`. DNS/PTR queries **bypass `ctx.rate` and `evidence.log`**.

### 8.2 `portscan` — `PortScanModule`

- **Flags:** `name="portscan"`, `phase="surface"`, `active=True`, `intrusive=False`.
- **Port precedence (`_ports`):** `scope.allowed_ports` (if non-empty) → `config.ports` (if non-empty) → `DEFAULT_PORTS` (41 ports). Scope allow-list wins over run config.
- **Catalog ids / findings:** `AEG-NET-001` (unconditional INFO "{n} open port(s) discovered", evidence lists `port/service`); `AEG-NET-002` (per sensitive port) titled "Sensitive service exposed: {label} (port {p})". Sensitive-port map (`_SENSITIVE`): 23 Telnet/HIGH, 3389 RDP/MEDIUM, 3306 MySQL/MEDIUM, 5432 PostgreSQL/MEDIUM, 6379 Redis/HIGH, 9200 Elasticsearch/HIGH, 27017 MongoDB/HIGH, 11211 Memcached/HIGH, 2375 Docker API/CRITICAL, 445 SMB/MEDIUM, 5900 VNC/HIGH. Sets `target.services`.
- **External tool + fallback:** optional **nmap** (`utils.have_tool`). Present → `_nmap`: `nmap -Pn -sT -sV --version-light -p <ports> -oX - <host>` via `subprocess.run(capture_output=True, text=True, timeout=max(60, config.timeout*10))`; on `SubprocessError`/`OSError` warns and falls back to `_native`. Does **not** check `returncode` — non-zero exit that still produced XML is parsed; a no-XML failure with no exception yields an empty list (no fallback). Absent → `_native`: per port `ctx.rate.acquire()` then `socket.create_connection((host, port), timeout=min(config.timeout, 3))`, `OSError` → skip. Native honors the rate limiter but not `evidence.log`; nmap does its own pacing (bypasses `ctx.rate`). `_parse_nmap_xml` keeps only `<state state="open">` ports, defaulting missing attributes to `""` / `portid="0"`, returns `[]` on empty input or `ET.ParseError`.

### 8.3 `tls_check` — `TlsModule`

- **Flags:** `name="tls_check"`, `phase="surface"`, `active=True`, `intrusive=False`. **Hard-codes host `target.host` and port 443** regardless of portscan/scope `allowed_ports`.
- **Catalog ids / findings:** `AEG-TLS-000` (INFO "No TLS on port 443", returned alone if no cert); `AEG-TLS-001` ("TLS certificate expiry" — parses `notAfter` via `strptime(..., "%b %d %H:%M:%S %Y %Z")` forced UTC; `days<0` HIGH/expired, `days<15` MEDIUM, else INFO; `ValueError` during parse silently skips; an empty cert dict → no `notAfter` → no expiry finding); `AEG-TLS-002` (MEDIUM "Legacy TLS protocol enabled: {name}", RFC 8996) per negotiated legacy protocol. `_LEGACY_PROTOCOLS` = SSLv3 (or `None` if unavailable, then skipped), TLSv1, TLSv1.1.
- **External tool + fallback:** none (stdlib `ssl`). `_cert_via_verifying` tries a verifying `ssl.create_default_context()`; on `OSError`/`ssl.SSLError` retries `ssl._create_unverified_context()` returning `getpeercert() or {}`; both failing → `None`. `_supports` pins `minimum=maximum=version` with `check_hostname=False`, `CERT_NONE`, returns handshake success. Up to four raw TLS handshakes; **bypass `ctx.rate`/`evidence.log`**; verification deliberately disabled in fallback/`_supports`.

### 8.4 `fingerprint` — `FingerprintModule`

- **Flags:** `name="fingerprint"`, `phase="surface"`, `active=True`, `intrusive=False`.
- **Catalog ids / findings:** `AEG-FP-001` (INFO "Technology fingerprint" when `tech` non-empty; writes `target.metadata["technologies"] = sorted(tech)`); `AEG-INFO-001` (LOW "Version/stack disclosure in HTTP headers", OWASP WSTG, when `leaks` non-empty).
- **External tool + fallback:** none; uses `ctx.request` (rate-limited, logged, `verify=False`, redirects followed). Tries schemes `("https", "http")` requesting `{scheme}://{host}`; processes the **first** non-`None` response then `break`s. **Appends `resp.url` (post-redirect) to `target.urls`** — cross-module state consumed by `nuclei` (`target.urls[0]`). Detects leaks from `_LEAKY_HEADERS` (server, x-powered-by, x-aspnet-version, x-aspnetmvc-version, x-generator, x-drupal-cache, x-runtime) and technologies from `_BODY_SIGNATURES` regexes over `resp.text[:200_000]` (WordPress, Drupal, Joomla, Next.js, Angular, React, Ruby on Rails). Gotcha: `technologies` mixes raw version strings and framework labels; only the first responsive scheme is analyzed.

### 8.5 `web_headers` — `WebHeadersModule`

- **Flags:** `name="web_headers"`, `phase="web"`, `active=True`, `intrusive=False`.
- **Catalog ids / findings:**
  - `AEG-HDR-001` — per missing security header in `_EXPECTED` (`strict-transport-security`/MEDIUM, `content-security-policy`/MEDIUM, `x-content-type-options`/LOW, `x-frame-options`/LOW, `referrer-policy`/INFO), OWASP Secure Headers.
  - `AEG-HDR-002` — LOW "Insecure cookie flags: {name}" per cookie missing `Secure` (`not cookie.secure`) or `HttpOnly` (`not cookie.has_nonstandard_attr("HttpOnly")`). SameSite is not checked despite remediation text.
  - `AEG-INFO-002` — sensitive-path exposure per `_PROBE_PATHS` (`/.git/HEAD`, `/.env`, `/robots.txt`, `/.well-known/security.txt`, `/server-status`, `/actuator/health`, `/phpinfo.php`); skips on `None` or `status>=400`; severity HIGH for `/.git/HEAD` & `/.env`, INFO for `/robots.txt` & security.txt, MEDIUM otherwise; `confidence=FIRM`; evidence = `repr` of first 120 body bytes (newlines→spaces). Gotcha: any 2xx/3xx counts as reachable (a redirect to login counts as exposed).
- **External tool + fallback:** none; uses `ctx.request`. Establishes base URL trying `https` then `http`; returns `[]` if neither responds. 1 base + up to 7 probe requests, all rate-limited and logged. No `Target` mutation.

### 8.6 `nuclei` — `NucleiModule`

- **Flags:** `name="nuclei"`, `phase="vuln"`, `active=True`, **`intrusive=True`** (the only intrusive module; requires scope `allow_intrusive: true` **and** `RunConfig.enable_intrusive=True`).
- **`available()`** → `(False, "nuclei binary not found on PATH")` if `utils.have_tool("nuclei")` is false, else `(True, "")`; the engine skips cleanly on a missing binary.
- **Catalog ids / findings:** `AEG-NUCLEI` — one finding per parsed match. Target URL = `target.urls[0]` if present (from fingerprint/web_headers) else `target.base_url()` (`https://{host}`). Command: `nuclei -u <url> -jsonl -silent -rate-limit <int(max(1, scope.max_rps))> -severity low,medium,high,critical -timeout <int(config.timeout)>` (rate from the **scope**, floored at 1; **excludes `info`**). `subprocess.run(..., timeout=1800)` (fixed 30-min cap); on `SubprocessError`/`OSError` warns and returns `[]`. Parses stdout JSONL (blank/invalid lines skipped; `returncode` not checked). `_to_finding` maps `info.severity` via `_SEV_MAP` (`unknown`→INFO), `references` from `info.reference` (coerced to list), `title` = `info.name` else `template-id` else "nuclei finding", fixed `category="Nuclei detection"`, `catalog_id="AEG-NUCLEI"`, `confidence=FIRM`, evidence = `matched-at: {matched-at or host}`.
- **External tool + fallback:** external **nuclei** (subprocess); pacing delegated to nuclei's `-rate-limit`; **bypasses `ctx.rate` and `evidence.log`**. Gotcha: all findings share `catalog_id="AEG-NUCLEI"` / category "Nuclei detection", so `_dedupe` (category+title+target) collapses two different templates that share a `name` on the same host.

---

## 9. CLI reference (`aegis/cli.py`)

Program `aegis` (console entry point `aegis.cli:main`). Global `--version` prints `aegis {__version__}` and exits (code 0). Subcommand is **required** (`dest="command"`, `required=True`) — no subcommand is an argparse usage error (exit 2). The CLI performs no direct network/subprocess I/O; all scanning side effects live in `Engine.run()`.

### 9.1 `aegis verify` — validate authorization + scope, no scanning

| Flag | Required | Default | Behavior |
|---|---|---|---|
| `--auth` | yes | — | Authorization YAML path. |
| `--scope` | yes | — | Scope YAML path. |
| `--signing-key` | no | `None` | Enforce HMAC signature. |
| `--target` | no (repeatable, `append`) | `[]` | Test each host against scope (informational). |

Behavior: `ScopeGuard.load(auth, scope, signing_key)` (filesystem read); `problems = guard.validate()`. If non-empty → prints "Authorization INVALID:" + each problem, returns **1**. Else prints a VALID banner + client, validity window (`valid_from…valid_until` isoformat), and comma-joined `in_scope`; for each `--target`, `guard.target_reason(t)` → "authorized" or "NOT authorized — {reason}" (purely informational — an unauthorized target does **not** change the exit code). Returns **0**.

### 9.2 `aegis run` — run an authorized assessment

| Flag | Required | Default | Behavior |
|---|---|---|---|
| `--auth` | yes | — | Authorization YAML path. |
| `--scope` | yes | — | Scope YAML path. |
| `--signing-key` | no | `None` | Enforce HMAC signature. |
| `--target` | **yes** (repeatable, `append`) | `[]` (never consulted) | Targets to assess. |
| `--out` | no | `"reports"` | Base output dir. |
| `--modules` | no | `None` | Comma-separated module subset (only `.strip()`ed, not validated). |
| `--timeout` | no (`float`) | `10.0` | Per-operation timeout. |
| `--enable-intrusive` | no (`store_true`) | false | Allow intrusive modules — **also requires scope `allow_intrusive`**. |

Behavior: `ScopeGuard.load(...)`; `guard.assert_valid()` inside a local `try` → on `AuthorizationError` prints the message and returns **1**. Builds `stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")`; `out_dir = Path(--out)/stamp` (the **same** `out_dir` object flows into both `RunConfig` and `write_reports`, guaranteeing identical directories). Builds `RunConfig(targets, out_dir, timeout, modules, enable_intrusive)`; `Engine(guard, config).run()` produces the findings; `write_reports(findings, guard, out_dir)` writes the files; prints "Reports written:" + each `kind: path`. Returns **0**.

### 9.3 `aegis catalog` — list/search the vulnerability catalog (no authorization needed)

| Flag | Required | Default | Behavior |
|---|---|---|---|
| `--search` | no | `None` | Case-insensitive keyword filter. |

Behavior: `load_catalog()`; `term = (--search or "").lower()`. Per category, includes a check if `term` is empty or a substring of the category name, check `id`, check `title`, or space-joined `techniques` (all lowercased). A matching **category name** lists all its checks. Prints `== {name} [{owasp}] ==` (bracket only if `owasp` truthy) then `  {id:<16} [{severity:<8}] {title}` per check (`severity` defaults `"?"`), tolerates missing keys via `.get`, then `"{total} catalog check(s) listed."` (`total` = displayed count). Always returns **0**.

### 9.4 `main(argv=None) -> int` and exit-code contract

Parses args, dispatches to the handler, wrapped in top-level handling: `FileNotFoundError` → "File not found: {exc}", **2**; `AuthorizationError` → `str(exc)`, **1**; `KeyboardInterrupt` → "Interrupted.", **130**. `AuthorizationError` is handled both locally in `_cmd_run` (for `assert_valid`) and at top level (e.g. from `ScopeGuard.load`) — both return 1.

| Exit code | Meaning |
|---|---|
| `0` | Success (valid verify / completed run / catalog listed). |
| `1` | Authorization invalid or assertion failed / uncaught `AuthorizationError`. |
| `2` | `FileNotFoundError`, or argparse usage error (incl. missing subcommand/required flags). |
| `130` | Interrupted with Ctrl-C (128 + SIGINT). |

`if __name__ == "__main__": sys.exit(main())`.

---

## 10. Reporting outputs (`aegis/reporting.py`)

`write_reports(findings, guard, out_dir) -> dict[str, Path]` is the sole entry point (called by `_cmd_run`). It `mkdir(parents=True, exist_ok=True)`s `out_dir`, tallies `counts = Counter(f.severity.label() …)`, builds a single shared `meta` snapshot (`engagement_id`, `client`, `authorized_by` from `guard.authorization`; `generated_at` UTC ISO-8601; `scope_hash = guard.scope.hash()`; `counts`; `total`), and writes three files, returning `{"json": …, "md": …, "html": …}`. All three share one `generated_at`/`scope_hash`/`counts`, so they are internally consistent. Each `aegis run` also produces `evidence.log` (written by the engine, truncated at run start).

| File | Format | Contents |
|---|---|---|
| `findings.json` | JSON (indent=2, UTF-8) | `{"meta": meta, "findings": [f.to_dict() for f in findings]}` — machine-readable. |
| `report.md` | Markdown (`_markdown`) | H1 "Security Assessment Report — {client}"; metadata bullets (engagement `or 'n/a'`, authorized_by, generated, scope hash truncated 16 chars + `…`, total + `_summary_line`); blockquote disclaimer ("Assessment performed under signed authorization. Non-destructive checks only."); `## Findings`; per finding H3 `### {i}. [{label}] {title}` + Target/Category/Module/Catalog(`or 'n/a'`)/Confidence(`.value`) + description + optional Evidence fenced block + optional Remediation + optional References. Empty → `_No findings recorded._` under the header. |
| `report.html` | Self-contained HTML5 (`_html`) | Standalone doc, inline `<style>`, dark theme, per-severity coloring from `_SEV_COLORS` (Critical `#8e0000`, High `#d9480f`, Medium `#e8a400`, Low `#2b8a3e`, Info `#495057`; unknown → gray). Header mirrors the MD metadata; summary chips from `summary.split('|')` (so `_summary_line`'s `" | "` delimiter is load-bearing); per-finding `.finding` card. **If jinja2 is unavailable, returns `"<pre>" + _markdown(...) + "</pre>"`** (degraded but valid). |
| `evidence.log` | JSONL | One `{ts, method, url, status, error}` record per sanctioned HTTP request (written by `ScanContext._log_evidence`; truncated at run start). |

`_summary_line(counts)` → `"Critical: N | High: N | Medium: N | Low: N | Info: N"` (fixed order, `counts.get(s, 0)` so absent labels render `0`). Reporting couples to `Finding.{severity.label(), confidence.value, to_dict(), title/target/category/module/catalog_id/description/evidence/remediation/references}` and `ScopeGuard.{authorization.*, scope.hash()}`.

**Security-relevant reporting notes:** Jinja2 autoescaping is **not** enabled — finding-supplied fields (`description`, `evidence`, `title`, `references` used as `href`) are injected without HTML escaping; the `<pre>` fallback likewise does not escape. Markdown evidence is emitted in an un-escaped triple-backtick block (content containing ``` can break the fence). These matter only if finding content is attacker-influenced. The HTML row dict, unlike Markdown, omits `confidence`.

---

## 11. Testing

Dev extras: `pytest>=8.0`, `ruff>=0.5`. The authoritative behavioral suite is `tests/test_authorization.py` — "Tests for the scope/authorization guard — the safety-critical core." It imports `Authorization, AuthorizationError, Scope, ScopeGuard` from `aegis.authorization`; all datetimes are timezone-aware UTC.

**Helper `_guard(**scope_kw)`** builds a `Scope` (defaults `in_scope=["example.com", "*.example.com", "203.0.113.0/24"]`, `out_of_scope=["status.example.com"]`, `allow_active=True`, `allow_intrusive=False`), an `Authorization` with an open window (`valid_from = now-1d`, `valid_until = now+1d`, `scope_hash = scope.hash()`), and returns a `ScopeGuard`. No network/filesystem/subprocess.

| Test | Asserts |
|---|---|
| `test_valid_engagement_has_no_problems` | Correctly-signed, in-window, non-empty → `validate() == []`. |
| `test_exact_host_in_scope` | `is_authorized("example.com")` is `True`. |
| `test_wildcard_subdomain_in_scope` | `is_authorized("app.example.com")` is `True` via `*.example.com`. |
| `test_out_of_scope_wins_over_wildcard` | `is_authorized("status.example.com")` is `False`; `target_reason` contains `"out of scope"`. |
| `test_unlisted_host_rejected` | `is_authorized("evil.test")` is `False`. |
| `test_scope_hash_tamper_detected` | After `g.scope.in_scope.append("newly-added.com")`, `validate()` contains `"scope_hash mismatch"`. |
| `test_expired_authorization_rejected` | `valid_until` = 1h ago → `validate()` contains `"expired"` and `assert_valid()` raises `AuthorizationError`. |
| `test_activity_gate_blocks_intrusive_by_default` | With `allow_intrusive=False`: active-only → `None` (allowed); intrusive → non-`None` (blocked). |
| `test_cidr_membership` | `203.0.113.42` authorized (inside `/24`); `203.0.114.1` not. |
| `test_empty_scope_is_invalid` | `in_scope=[]` → `validate()` contains `"in_scope is empty"`. |

These tests establish the load-bearing behaviors: exact/wildcard/CIDR matching, out-of-scope precedence, tamper detection via scope-hash mismatch, expiry enforcement (`validate()` reports; `assert_valid()` raises), and the intrusive activity gate defaulting closed.

---

## 12. Extension guide — adding a module

1. Create `aegis/modules/<yourmodule>.py` with a class subclassing `aegis.modules.base.Module`.
2. Set class attributes: a unique `name` (used for CLI `--modules` filtering, reports, logging), a `phase` label, and the honest `active` / `intrusive` flags. `active=True` means you send target traffic (gated by scope `allow_active`); `intrusive=True` means noisy/heavy probing (gated by **both** scope `allow_intrusive` **and** run `--enable-intrusive`).
3. If you depend on an external binary or optional package, override `available() -> tuple[bool, str]` to return `(False, reason)` when it is missing — the engine will skip cleanly and log the reason (follow `NucleiModule`).
4. Implement `run(self, target, ctx) -> list[Finding]`. Use **`ctx.request(method, url, **kwargs)`** for HTTP so the rate limiter and `evidence.log` are honored (using `ctx.session` directly bypasses the audit log). Handle a `None` response (network failure). Read config via `ctx.config` and scope via `ctx.guard.scope`. You may enrich the shared `Target` (`target.services`, `target.urls`, `target.metadata`) — note `fingerprint`/`web_headers` populate `target.urls`, which `nuclei` consumes.
5. Produce `Finding` objects with a stable `catalog_id` and set `category`/`title`/`target` deliberately — those three form the dedup `key` (differences in module/severity/evidence do **not** create distinct findings).
6. Add a matching catalog entry in `catalog/vulnerabilities.yaml` (with `id`, `severity`, `automated: true`, `module: <name>`, techniques/detection/remediation/references) so findings correlate.
7. Register the class in `Engine._select_modules()`'s fixed registry list — its position in that list is its execution order per target.
8. Do not raise for expected conditions (swallow tool/network errors internally); any exception that escapes `run` is caught by the engine's fail-safe wrapper, logged, and the run continues. Keep the module non-destructive and within the rate cap.

---

## 13. Operational invariants (what must NEVER break)

1. **No target is ever touched without passing the guard.** `Engine.run()` calls `guard.assert_valid()` before any I/O, and each target must pass `guard.target_reason(host) is None`. There is no override flag anywhere in the codebase.
2. **Scope tamper-evidence holds.** Editing `scope.yaml` after signing changes `scope.hash()` and fails `validate()`'s constant-time `scope_hash` comparison. Widening scope post-sign is detectable and blocked.
3. **The time window is enforced.** A run outside `[valid_from, valid_until]` fails `assert_valid()`.
4. **The intrusive two-key interlock stays intact.** `nuclei` (and any `intrusive=True` module) runs only when scope `allow_intrusive: true` **and** `--enable-intrusive` are both set; either alone is insufficient.
5. **Fail-safe, never fail-stop.** An exception in one module's `run` is caught and logged; the assessment continues. Missing optional tools/packages are clean skips, not crashes. Only `KeyboardInterrupt`/`SystemExit` propagate.
6. **The rate cap is honored.** All sanctioned framework HTTP passes through the shared `RateLimiter` built from the signed scope's `max_rps` (floored at 0.1); nuclei is separately pinned to `-rate-limit int(max(1, scope.max_rps))`.
7. **Every sanctioned HTTP request is audited.** `ctx.request` appends to `evidence.log`; the log is truncated fresh at the start of each run and its path equals the report directory.
8. **Non-destructive only.** No DoS, no data modification, no persistence, no detection-evasion, no mass/untargeted scanning — the probe set is read-only and the target list is explicit and finite.
9. **Findings are deduplicated and severity-sorted** by `_dedupe` (first-wins per `category|title|target` key; highest severity first) before reaching reports.
10. **Real engagement data never leaks into version control.** `config/authorization.yaml`, `config/scope.yaml`, `reports/*/`, and `*.log` are git-ignored; only `.example.yaml` templates and `reports/.gitkeep` are tracked.
11. **Authorization reports, it does not crash.** `validate()` returns a list of problems (empty = valid) and never raises; only `assert_valid()` raises `AuthorizationError`.
12. **The framework runs (degraded) without optional deps.** rich → plain print; dnspython → resolved-IP fallback; jinja2 → `<pre>` HTML; nmap → native connect scan; nuclei absent → skipped. PyYAML and requests are the only hard runtime requirements.
