"""SPF / DKIM / DMARC analysis."""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult

DEFAULT_DKIM_SELECTORS = (
    "default", "google", "mail", "selector1", "selector2", "k1", "dkim",
    "smtp", "amazonses",
)


def _txt(host: str, *, timeout: int = 10) -> list[str]:
    r = run_cmd(["dig", "+short", "TXT", host], timeout=timeout)
    out: list[str] = []
    for line in r.stdout.splitlines():
        line = line.strip().strip('"')
        if line:
            out.append(line)
    return out


def query(domain: str, *, dkim_selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS,
          timeout: int = 10) -> dict:
    spf = [t for t in _txt(domain, timeout=timeout) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _txt(f"_dmarc.{domain}", timeout=timeout) if t.lower().startswith("v=dmarc1")]
    dkim_present: dict[str, str] = {}
    for sel in dkim_selectors:
        records = _txt(f"{sel}._domainkey.{domain}", timeout=timeout)
        for rec in records:
            if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                dkim_present[sel] = rec
                break
    return {"domain": domain, "spf": spf, "dkim": dkim_present, "dmarc": dmarc}


def _spf_strictness(records: list[str]) -> tuple[str, str]:
    """Return (label, value_marker_used)."""
    if not records:
        return ("missing", "")
    text = " ".join(records).lower()
    if "+all" in text:
        return ("permissive_plus_all", "+all")
    if "?all" in text:
        return ("neutral_qmark_all", "?all")
    if "~all" in text:
        return ("soft_fail_tilde_all", "~all")
    if "-all" in text:
        return ("strict_minus_all", "-all")
    return ("ambiguous", "")


def _dmarc_policy(records: list[str]) -> str:
    if not records:
        return "missing"
    blob = " ".join(records).lower()
    if "p=reject" in blob:
        return "reject"
    if "p=quarantine" in blob:
        return "quarantine"
    if "p=none" in blob:
        return "none"
    return "ambiguous"


def _draft_findings(domain: str, data: dict) -> list[FindingDraft]:
    out: list[FindingDraft] = []
    spf_label, marker = _spf_strictness(data["spf"])
    dmarc_label = _dmarc_policy(data["dmarc"])
    if spf_label == "missing":
        out.append(FindingDraft(
            title=f"Missing SPF record on {domain}",
            severity="high", cwe="CWE-290",
            affected_component=f"DNS TXT record for {domain}",
            description="No SPF record exists. Any server in the world can send email claiming to be from this domain.",
            remediation="Publish a SPF record listing authorised mail sources, terminating with -all.",
            references=["https://datatracker.ietf.org/doc/html/rfc7208"],
        ))
    elif spf_label in ("permissive_plus_all", "neutral_qmark_all"):
        out.append(FindingDraft(
            title=f"Weak SPF policy ({marker}) on {domain}",
            severity="high" if spf_label == "permissive_plus_all" else "medium",
            cwe="CWE-290",
            affected_component=f"DNS TXT record for {domain}",
            description=f"SPF terminates with '{marker}', which does not enforce sender authorisation.",
            remediation="Tighten SPF to terminate with -all (strict) or ~all (soft-fail).",
        ))
    if dmarc_label == "missing":
        out.append(FindingDraft(
            title=f"Missing DMARC record on {domain}",
            severity="high", cwe="CWE-290",
            affected_component=f"DNS TXT record for _dmarc.{domain}",
            description="No DMARC record. Receiving servers cannot enforce alignment between SPF/DKIM and the From header.",
            remediation="Publish a DMARC record at _dmarc.<domain>. Start with p=none for monitoring, escalate to p=quarantine then p=reject.",
            references=["https://datatracker.ietf.org/doc/html/rfc7489"],
        ))
    elif dmarc_label == "none":
        out.append(FindingDraft(
            title=f"Weak DMARC policy (p=none) on {domain}",
            severity="medium", cwe="CWE-290",
            affected_component=f"DNS TXT record for _dmarc.{domain}",
            description="DMARC policy is p=none, which only requests reporting and does not block spoofed mail.",
            remediation="Move to p=quarantine then p=reject after monitoring DMARC reports for legitimate sources.",
        ))
    if not data["dkim"]:
        out.append(FindingDraft(
            title=f"No DKIM selectors detected for {domain}",
            severity="medium", cwe="CWE-345",
            affected_component=f"DNS DKIM selectors at *._domainkey.{domain}",
            description="None of the common DKIM selectors returned a v=DKIM1 record. Outbound mail likely lacks DKIM signing.",
            remediation="Configure DKIM signing on outbound mail sources; publish the selector public key in DNS.",
        ))
    return out


def run(ctx: ModuleContext) -> ModuleResult:
    domain = (ctx.params or {}).get("domain") or (ctx.params or {}).get("host")
    if not domain:
        return ModuleResult(success=False, error="missing required param 'domain'")
    if not tool_available("dig"):
        return ModuleResult(success=False, error="dig not installed")

    data = query(domain)
    findings = _draft_findings(domain, data)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"email_security_{domain.replace('.', '_')}_{ts}.json"
    write_artifact(json_path, json.dumps(data, indent=2))

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="email security records", host=ctx.worker_host)],
        summary=f"email_security {domain}: SPF={'yes' if data['spf'] else 'no'} DMARC={_dmarc_policy(data['dmarc'])} DKIM={len(data['dkim'])} selector(s); {len(findings)} draft finding(s)",
    )
