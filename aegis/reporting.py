"""Report generation: JSON, Markdown and a self-contained HTML report."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .authorization import ScopeGuard
from .models import Finding, Severity

_SEV_COLORS = {
    "Critical": "#8e0000",
    "High": "#d9480f",
    "Medium": "#e8a400",
    "Low": "#2b8a3e",
    "Info": "#495057",
}


def write_reports(
    findings: list[Finding], guard: ScopeGuard, out_dir: Path
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter(f.severity.label() for f in findings)
    meta = {
        "engagement_id": guard.authorization.engagement_id,
        "client": guard.authorization.client,
        "authorized_by": guard.authorization.authorized_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope_hash": guard.scope.hash(),
        "counts": dict(counts),
        "total": len(findings),
    }

    paths = {
        "json": out_dir / "findings.json",
        "md": out_dir / "report.md",
        "html": out_dir / "report.html",
    }
    paths["json"].write_text(
        json.dumps(
            {"meta": meta, "findings": [f.to_dict() for f in findings]},
            indent=2,
        ),
        encoding="utf-8",
    )
    paths["md"].write_text(_markdown(findings, meta), encoding="utf-8")
    paths["html"].write_text(_html(findings, meta), encoding="utf-8")
    return paths


def _summary_line(counts: dict[str, int]) -> str:
    order = ["Critical", "High", "Medium", "Low", "Info"]
    return " | ".join(f"{s}: {counts.get(s, 0)}" for s in order)


def _markdown(findings: list[Finding], meta: dict) -> str:
    lines = [
        f"# Security Assessment Report — {meta['client']}",
        "",
        f"- **Engagement:** {meta['engagement_id'] or 'n/a'}",
        f"- **Authorized by:** {meta['authorized_by']}",
        f"- **Generated:** {meta['generated_at']}",
        f"- **Scope hash:** `{meta['scope_hash'][:16]}…`",
        f"- **Findings:** {meta['total']} ({_summary_line(meta['counts'])})",
        "",
        "> Assessment performed under signed authorization. Non-destructive checks only.",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("_No findings recorded._")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.severity.label()}] {f.title}",
            "",
            f"- **Target:** {f.target}",
            f"- **Category:** {f.category}",
            f"- **Module:** {f.module}",
            f"- **Catalog:** {f.catalog_id or 'n/a'}",
            f"- **Confidence:** {f.confidence.value}",
            "",
            f"{f.description}",
            "",
        ]
        if f.evidence:
            lines += ["**Evidence:**", "", "```", f.evidence, "```", ""]
        if f.remediation:
            lines += [f"**Remediation:** {f.remediation}", ""]
        if f.references:
            lines += ["**References:**"] + [f"- {r}" for r in f.references] + [""]
    return "\n".join(lines)


def _html(findings: list[Finding], meta: dict) -> str:
    try:
        from jinja2 import Template
    except Exception:
        # Minimal fallback if jinja2 is unavailable.
        return "<pre>" + _markdown(findings, meta) + "</pre>"

    template = Template(_HTML_TEMPLATE)
    rows = []
    for f in findings:
        rows.append(
            {
                "title": f.title,
                "sev": f.severity.label(),
                "color": _SEV_COLORS.get(f.severity.label(), "#495057"),
                "target": f.target,
                "category": f.category,
                "module": f.module,
                "catalog_id": f.catalog_id or "",
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "references": f.references,
            }
        )
    return template.render(meta=meta, findings=rows, summary=_summary_line(meta["counts"]))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Report — {{ meta.client }}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; background:#0f1115; color:#e6e6e6; }
  header { padding: 24px; background:#161a22; border-bottom:1px solid #2a2f3a; }
  h1 { margin:0 0 8px; font-size:20px; }
  .meta { color:#9aa4b2; font-size:13px; line-height:1.7; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px; }
  .summary span { display:inline-block; padding:4px 10px; border-radius:6px; margin:4px 6px 0 0;
     font-size:12px; background:#222834; }
  .finding { background:#161a22; border:1px solid #2a2f3a; border-left:5px solid;
     border-radius:8px; padding:16px 18px; margin:16px 0; }
  .badge { display:inline-block; padding:2px 8px; border-radius:5px; color:#fff; font-size:11px;
     font-weight:600; letter-spacing:.4px; }
  .kv { color:#9aa4b2; font-size:12px; margin:8px 0; }
  pre { background:#0b0d11; border:1px solid #2a2f3a; padding:10px; border-radius:6px;
     overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
  a { color:#4dabf7; }
  .rem { color:#c3f0c8; font-size:13px; }
</style></head>
<body>
<header><div class="wrap">
  <h1>Security Assessment Report — {{ meta.client }}</h1>
  <div class="meta">
    Engagement: {{ meta.engagement_id or 'n/a' }} &middot;
    Authorized by: {{ meta.authorized_by }} &middot;
    Generated: {{ meta.generated_at }}<br>
    Scope hash: <code>{{ meta.scope_hash[:16] }}…</code> &middot;
    Total findings: {{ meta.total }}
  </div>
  <div class="summary" style="margin-top:10px;">
    {% for part in summary.split('|') %}<span>{{ part.strip() }}</span>{% endfor %}
  </div>
</div></header>
<div class="wrap">
{% if not findings %}<p>No findings recorded.</p>{% endif %}
{% for f in findings %}
  <div class="finding" style="border-left-color: {{ f.color }};">
    <span class="badge" style="background: {{ f.color }};">{{ f.sev }}</span>
    <strong style="margin-left:8px;">{{ f.title }}</strong>
    <div class="kv">Target: {{ f.target }} &middot; Category: {{ f.category }}
      &middot; Module: {{ f.module }}{% if f.catalog_id %} &middot; {{ f.catalog_id }}{% endif %}</div>
    <div>{{ f.description }}</div>
    {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
    {% if f.remediation %}<div class="rem">Remediation: {{ f.remediation }}</div>{% endif %}
    {% if f.references %}<div class="kv">Refs:
      {% for r in f.references %}<a href="{{ r }}">{{ r }}</a> {% endfor %}</div>{% endif %}
  </div>
{% endfor %}
</div>
</body></html>
"""
