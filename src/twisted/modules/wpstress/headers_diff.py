"""Stressed-state header diff vs the Phase 1 baseline.

Reads the most recent baseline headers JSON written by
``recon.headers_audit`` for the same engagement (via the engine's
artifact registry) and re-runs the audit, flagging any new headers
that appear (often error-state info disclosure: PHP versions, debug
info, stack traces).
"""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult
from ..recon.headers_audit import audit_headers

_LEAKY_HEADERS = ("X-Powered-By", "Server", "X-AspNet-Version", "X-Generator", "X-Debug-Token")


def diff(baseline_headers: dict, stressed_headers: dict) -> dict:
    """Return added/changed/removed header keys + values."""
    base_lc = {k.lower(): v for k, v in (baseline_headers or {}).items()}
    stress_lc = {k.lower(): v for k, v in (stressed_headers or {}).items()}
    added = {k: stress_lc[k] for k in stress_lc if k not in base_lc}
    removed = {k: base_lc[k] for k in base_lc if k not in stress_lc}
    changed = {k: {"baseline": base_lc[k], "stressed": stress_lc[k]}
               for k in (set(base_lc) & set(stress_lc)) if base_lc[k] != stress_lc[k]}
    return {"added": added, "changed": changed, "removed": removed}


def run(ctx: ModuleContext) -> ModuleResult:
    host = (ctx.params or {}).get("host") or (ctx.params or {}).get("url")
    if not host:
        return ModuleResult(success=False, error="missing required param 'host'")
    baseline_headers = (ctx.params or {}).get("baseline_headers") or {}

    # Capture stressed-state headers
    stressed = audit_headers(host)
    headers_now = stressed.get("headers", {})

    diffed = diff(baseline_headers, headers_now)
    findings: list[FindingDraft] = []
    for k, v in diffed["added"].items():
        if any(k.lower() == leaky.lower() for leaky in _LEAKY_HEADERS):
            findings.append(FindingDraft(
                title=f"Information disclosure header appeared under load: {k} on {host}",
                severity="medium",
                cwe="CWE-200",
                affected_component=f"https://{host}",
                description=f"The header '{k}: {v}' was not present in the baseline but appeared under stress.",
                remediation="Suppress the header (ServerTokens Prod / expose_php=Off / framework-specific).",
            ))

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"headers_diff_{host.replace('.', '_')}_{ts}.json"
    write_artifact(json_path, json.dumps({
        "host": host, "baseline": baseline_headers,
        "stressed": headers_now, "diff": diffed,
    }, indent=2))

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="headers diff", host=ctx.worker_host)],
        summary=(f"headers_diff {host}: added={len(diffed['added'])} "
                 f"changed={len(diffed['changed'])} removed={len(diffed['removed'])}; "
                 f"{len(findings)} draft finding(s)"),
        extra=diffed,
    )
