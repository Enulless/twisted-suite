"""WordPress remediation matrix generator.

Pulls all findings for the engagement and produces a prioritised
remediation plan following the wp_stress_procedure.docx Phase 4 matrix:
severity -> example finding -> remediation -> fix-by target.
"""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from .._engine_callback import get_client
from ..base import EvidenceRef, ModuleContext, ModuleResult

# Severity -> default fix-by interval (days)
_FIX_BY = {
    "critical": 1,
    "high":     7,
    "medium":   30,
    "low":      90,
    "info":     180,
}

# Heuristic mapping: keywords in finding title -> remediation hint
_REMEDIATION_HINTS = [
    ("wp-config",   "Restrict via .htaccess (deny from all) or NGINX deny rule"),
    ("xmlrpc",      "Disable via .htaccess or use plugin to disable XML-RPC"),
    ("debug.log",   "Set WP_DEBUG=false; remove the file"),
    (".env",        "Move outside web root; restrict via web-server config"),
    ("plugin",      "Update or remove the plugin"),
    ("theme",       "Update the theme or switch to a maintained alternative"),
    ("X-Powered-By","Set expose_php = Off in php.ini"),
    ("Server",      "Set ServerTokens Prod (Apache) or server_tokens off (NGINX)"),
    ("CSP",         "Define a Content-Security-Policy"),
    ("HSTS",        "Enable Strict-Transport-Security with includeSubDomains"),
    ("X-Frame",     "Set X-Frame-Options: SAMEORIGIN"),
    ("CORS",        "Restrict Access-Control-Allow-Origin to trusted origins"),
    ("DKIM",        "Configure DKIM signing on outbound mail"),
    ("DMARC",       "Publish a DMARC record at _dmarc.<domain>"),
    ("SPF",         "Publish/tighten the SPF record (terminate with -all)"),
]


def _hint_for(title: str) -> str:
    lower = title.lower()
    for kw, hint in _REMEDIATION_HINTS:
        if kw.lower() in lower:
            return hint
    return "Manual investigation required"


def build_matrix(ctx: ModuleContext) -> ModuleResult:
    engagement_id = (ctx.params or {}).get("engagement_id") or ctx.engagement_id
    if not engagement_id:
        return ModuleResult(success=False, error="missing required param 'engagement_id'")

    client = get_client()
    try:
        findings = client.get(f"/engagements/{engagement_id}/findings")
    except Exception as e:  # noqa: BLE001
        return ModuleResult(success=False, error=f"engine fetch failed: {e}")

    rows = []
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        rows.append({
            "id": f["id"],
            "title": f["title"],
            "severity": sev,
            "remediation": _hint_for(f["title"]),
            "fix_by_days": _FIX_BY.get(sev, 180),
            "status": f.get("status", "open"),
        })

    rows.sort(key=lambda r: (_FIX_BY.get(r["severity"], 999), r["title"]))

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"remediation_matrix_{ts}.json"
    md_path = ctx.work_dir / f"remediation_matrix_{ts}.md"
    write_artifact(json_path, json.dumps(rows, indent=2))

    md_lines = ["# Remediation Matrix\n",
                "| ID | Severity | Fix by (days) | Title | Remediation hint |",
                "|---|---|---|---|---|"]
    for r in rows:
        md_lines.append(f"| {r['id']} | {r['severity']} | {r['fix_by_days']} | "
                         f"{r['title']} | {r['remediation']} |")
    write_artifact(md_path, "\n".join(md_lines))

    return ModuleResult(
        success=True,
        artifacts=[json_path, md_path],
        evidence=[EvidenceRef(path=to_canonical(md_path), kind="file",
                              note="remediation matrix", host=ctx.worker_host)],
        summary=f"remediation_matrix: {len(rows)} finding(s) prioritised",
        extra={"finding_count": len(rows)},
    )
