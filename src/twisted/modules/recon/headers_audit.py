"""Security headers audit.

Mirrors the bug-bounty Stage 3 Procedure A header check. Inspects the
canonical set of HTTP security headers and emits a finding draft for
each missing one (low/medium severity per the procedure scoring matrix).
"""

from __future__ import annotations

import json

import requests
import urllib3

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
)

# Map missing-header → (CWE, severity, default remediation)
HEADER_GUIDANCE = {
    "Strict-Transport-Security": ("CWE-319", "low",
        "Add Strict-Transport-Security with includeSubDomains and a long max-age (>= 6 months)."),
    "Content-Security-Policy": ("CWE-1021", "medium",
        "Define a Content-Security-Policy that restricts script/style/connect sources."),
    "X-Frame-Options": ("CWE-1021", "low",
        "Set X-Frame-Options: SAMEORIGIN (or use frame-ancestors in CSP)."),
    "X-Content-Type-Options": ("CWE-693", "low",
        "Set X-Content-Type-Options: nosniff to prevent MIME-sniffing."),
    "Referrer-Policy": ("CWE-200", "low",
        "Set Referrer-Policy to strict-origin-when-cross-origin or stricter."),
    "Permissions-Policy": ("CWE-693", "low",
        "Configure a Permissions-Policy to restrict access to sensitive browser APIs."),
}


def audit_headers(host: str, *, timeout: int = 10,
                  user_agent: str = "TwistedRecon/0.1",
                  session: requests.Session | None = None) -> dict:
    sess = session or requests.Session()
    url = f"https://{host}"
    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False,
                     headers={"User-Agent": user_agent})
    except Exception as e:  # noqa: BLE001
        return {"host": host, "error": str(e)[:200], "headers": {}, "missing": [], "present": []}
    hdrs_lower = {k.lower(): v for k, v in r.headers.items()}
    present: dict[str, str] = {}
    missing: list[str] = []
    for h in SECURITY_HEADERS:
        v = hdrs_lower.get(h.lower())
        if v:
            present[h] = v
        else:
            missing.append(h)
    cors_wildcard = hdrs_lower.get("access-control-allow-origin") == "*"
    return {
        "host": host,
        "status": r.status_code,
        "headers": dict(r.headers),
        "present": present,
        "missing": missing,
        "cors_wildcard": cors_wildcard,
    }


def _draft_findings(audit: dict) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    host = audit.get("host", "?")
    for h in audit.get("missing", []):
        if h not in HEADER_GUIDANCE:
            continue
        cwe, sev, remediation = HEADER_GUIDANCE[h]
        drafts.append(FindingDraft(
            title=f"Missing {h} header on {host}",
            severity=sev,
            cwe=cwe,
            affected_component=f"https://{host}",
            description=f"The HTTPS response from {host} does not include the {h} header.",
            remediation=remediation,
            references=[f"https://owasp.org/www-project-secure-headers/#{h.lower()}"],
        ))
    if audit.get("cors_wildcard"):
        drafts.append(FindingDraft(
            title=f"Wildcard CORS (Access-Control-Allow-Origin: *) on {host}",
            severity="medium",
            cwe="CWE-942",
            affected_component=f"https://{host}",
            description=(
                "The server replies with Access-Control-Allow-Origin: *, "
                "permitting cross-origin reads from any web origin."
            ),
            remediation=(
                "Restrict the Access-Control-Allow-Origin header to a specific "
                "trusted origin or set of origins."
            ),
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        ))
    return drafts


def run(ctx: ModuleContext) -> ModuleResult:
    hosts: list[str] = (ctx.params or {}).get("hosts") or []
    single_host = (ctx.params or {}).get("host")
    if single_host and single_host not in hosts:
        hosts = [single_host, *hosts]
    if not hosts:
        return ModuleResult(success=False, error="missing required param 'host' or 'hosts'")

    if ctx.scope is not None:
        kept, _ = ctx.scope.filter(hosts)
        hosts = kept

    sess = requests.Session()
    audits = [audit_headers(h, session=sess) for h in hosts]

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"headers_audit_{ts}.json"
    txt_path = ctx.work_dir / f"headers_audit_{ts}.txt"
    write_artifact(json_path, json.dumps(audits, indent=2))

    txt_lines = []
    for a in audits:
        txt_lines.append(f"\n── {a.get('host')} ──")
        if a.get("error"):
            txt_lines.append(f"  ERROR: {a['error']}")
            continue
        for h in SECURITY_HEADERS:
            value = a["present"].get(h)
            mark = "OK " if value else "MISSING "
            txt_lines.append(f"  {mark}{h}: {value or ''}")
        if a.get("cors_wildcard"):
            txt_lines.append("  [!] CORS wildcard origin")
    write_artifact(txt_path, "\n".join(txt_lines))

    findings: list[FindingDraft] = []
    for a in audits:
        findings.extend(_draft_findings(a))

    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        findings=findings,
        evidence=[
            EvidenceRef(path=to_canonical(json_path), kind="command_output",
                        note="headers audit JSON", host=ctx.worker_host),
        ],
        summary=f"headers_audit: {len(hosts)} host(s); {len(findings)} draft finding(s)",
    )
