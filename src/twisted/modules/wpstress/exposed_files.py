"""Exposed sensitive-file probe.

A 200/401/403 on any of the canonical sensitive paths is a finding.
We keep this network-only (no auth) so it stays passive and safe.
"""

from __future__ import annotations

import json

import requests
import urllib3

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SENSITIVE_PATHS = (
    ("wp-config.php.bak",       "critical", "WordPress config backup"),
    ("wp-config.php~",          "critical", "WordPress config backup"),
    ("wp-config.txt",           "critical", "WordPress config backup"),
    (".env",                    "critical", "Environment file"),
    ("debug.log",               "high",     "Debug log"),
    ("wp-content/debug.log",    "high",     "WordPress debug log"),
    ("xmlrpc.php",              "medium",   "XML-RPC endpoint (often used in pingback DoS)"),
    (".git/config",             "high",     "Exposed git directory"),
    (".git/HEAD",               "high",     "Exposed git directory"),
    ("backup.zip",              "critical", "Site backup archive"),
    ("backup.tar.gz",           "critical", "Site backup archive"),
    ("install.php",             "high",     "WordPress installer left exposed"),
    ("readme.html",             "low",      "WordPress readme (version disclosure)"),
)


def _normalise(host: str) -> str:
    if "://" not in host:
        return f"https://{host}"
    return host.rstrip("/")


def probe(host: str, *, timeout: int = 10,
          session: requests.Session | None = None) -> list[dict]:
    sess = session or requests.Session()
    base = _normalise(host)
    results: list[dict] = []
    for path, severity, label in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=False, verify=False)
            results.append({"url": url, "status": r.status_code,
                            "content_length": len(r.content),
                            "severity": severity, "label": label})
        except Exception as e:  # noqa: BLE001
            results.append({"url": url, "status": None, "error": str(e)[:80],
                            "severity": severity, "label": label})
    return results


def _draft_findings(results: list[dict], host: str) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for r in results:
        status = r.get("status")
        if status not in (200, 401, 403):
            continue
        # 401/403 is still a finding (file exists, just protected)
        sev = r["severity"] if status == 200 else "low"
        drafts.append(FindingDraft(
            title=f"Sensitive file exposed: {r['label']} ({r['url']})",
            severity=sev,
            cwe="CWE-200",
            affected_component=r["url"],
            description=(f"HTTP {status} for {r['url']}. "
                         f"This path should not be reachable from the internet."),
            remediation=(f"Restrict access to {r['url'].rsplit('/',1)[-1]} via "
                         f".htaccess / NGINX deny / move outside the web root."),
        ))
    return drafts


def run(ctx: ModuleContext) -> ModuleResult:
    host = (ctx.params or {}).get("host") or (ctx.params or {}).get("url")
    if not host:
        return ModuleResult(success=False, error="missing required param 'host'")

    results = probe(host)
    findings = _draft_findings(results, host)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"exposed_files_{host.replace('.', '_').replace('/', '_')}_{ts}.json"
    write_artifact(json_path, json.dumps({"host": host, "results": results}, indent=2))

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="exposed files probe", host=ctx.worker_host)],
        summary=(f"exposed_files {host}: probed {len(results)} path(s); "
                 f"{len(findings)} exposed"),
        extra={"hits": [r for r in results if r.get("status") in (200, 401, 403)]},
    )
