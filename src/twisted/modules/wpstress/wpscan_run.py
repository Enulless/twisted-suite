"""WPScan wrapper.

WPScan supports JSON output via `--format json`; we parse it for
plugins, themes, users, and core CVEs and emit finding drafts for
every vulnerability with a known CVE.
"""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult


def _normalise(host: str) -> str:
    if "://" not in host:
        return f"https://{host}"
    return host.rstrip("/")


def _draft_findings(payload: dict, host: str) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []

    # Core CVEs
    for v in (payload.get("version", {}) or {}).get("vulnerabilities", []) or []:
        title = v.get("title") or "WordPress core vulnerability"
        cves = v.get("references", {}).get("cve") or []
        sev = "high" if cves else "medium"
        drafts.append(FindingDraft(
            title=f"WordPress core: {title}",
            severity=sev, cwe=None,
            affected_component=_normalise(host),
            description=v.get("description") or "",
            references=[f"https://nvd.nist.gov/vuln/detail/CVE-{cve}" for cve in cves],
        ))

    # Plugin CVEs
    for plug_slug, plug in (payload.get("plugins") or {}).items():
        version = (plug.get("version") or {}).get("number")
        for v in (plug.get("vulnerabilities") or []):
            title = v.get("title") or f"{plug_slug} vulnerability"
            cves = v.get("references", {}).get("cve") or []
            drafts.append(FindingDraft(
                title=f"WordPress plugin {plug_slug} {version or ''}: {title}",
                severity="high",
                cwe=None,
                affected_component=_normalise(host),
                description=v.get("description") or "",
                references=[f"https://nvd.nist.gov/vuln/detail/CVE-{cve}" for cve in cves],
                remediation=f"Update plugin '{plug_slug}' to the patched version or remove if unused.",
            ))

    # Theme CVEs (same shape as plugins)
    for theme_slug, theme in (payload.get("themes") or {}).items():
        version = (theme.get("version") or {}).get("number")
        for v in (theme.get("vulnerabilities") or []):
            cves = v.get("references", {}).get("cve") or []
            drafts.append(FindingDraft(
                title=f"WordPress theme {theme_slug} {version or ''}: {v.get('title', 'vulnerability')}",
                severity="high", cwe=None,
                affected_component=_normalise(host),
                description=v.get("description") or "",
                references=[f"https://nvd.nist.gov/vuln/detail/CVE-{cve}" for cve in cves],
                remediation=f"Update theme '{theme_slug}' or switch themes.",
            ))

    return drafts


def run(ctx: ModuleContext) -> ModuleResult:
    host = (ctx.params or {}).get("host") or (ctx.params or {}).get("url")
    if not host:
        return ModuleResult(success=False, error="missing required param 'host'")
    if not tool_available("wpscan"):
        return ModuleResult(success=False, error="wpscan not installed (gem install wpscan)")

    api_token = (ctx.params or {}).get("api_token")
    detection = (ctx.params or {}).get("plugins_detection", "passive")
    target = _normalise(host)
    cmd = [
        "wpscan", "--url", target,
        "--format", "json",
        "--enumerate", "vp,vt,tt,cb,dbe,u",
        "--plugins-detection", detection,
        "--no-update",
    ]
    if api_token:
        cmd += ["--api-token", api_token]

    timeout = int((ctx.params or {}).get("timeout", 600))
    r = run_cmd(cmd, timeout=timeout)

    parsed: dict = {}
    parse_error: str | None = None
    if r.stdout.strip().startswith("{"):
        try:
            parsed = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            parse_error = f"json parse error: {e}"
    else:
        parse_error = "wpscan did not produce JSON output"

    findings = _draft_findings(parsed, host) if parsed else []

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"wpscan_{host.replace('.', '_').replace('/', '_')}_{ts}.json"
    txt_path = ctx.work_dir / f"wpscan_{host.replace('.', '_').replace('/', '_')}_{ts}.txt"
    write_artifact(json_path, r.stdout or "{}")
    write_artifact(txt_path, r.stderr or "")

    if parse_error and not parsed:
        return ModuleResult(
            success=False,
            error=parse_error,
            artifacts=[json_path, txt_path],
            summary=f"wpscan {target}: {parse_error}",
        )

    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="wpscan json", host=ctx.worker_host)],
        summary=(f"wpscan {target}: {len(findings)} draft finding(s); "
                 f"plugins={len(parsed.get('plugins') or {})}, "
                 f"themes={len(parsed.get('themes') or {})}"),
        extra={"finding_count": len(findings)},
    )
