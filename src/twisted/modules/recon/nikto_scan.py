"""Nikto web server scanner wrapper.

Parses Nikto's plain output into a list of finding drafts. We treat
every "+ <message>" line as a candidate finding; OSVDB and CVE
references are extracted into the references list when present.
"""

from __future__ import annotations

import json
import re

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, FindingDraft, ModuleContext, ModuleResult

_OSVDB_RE = re.compile(r"OSVDB-(\d+)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_HIGH_KEYWORDS = ("admin", "default", "vulnerable", "injection", "traversal", "exploit", "remote", "rce")


def parse(output: str) -> list[dict]:
    items: list[dict] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line or not line.startswith("+ "):
            continue
        message = line[2:].strip()
        # Skip pure metadata lines
        if any(message.lower().startswith(p) for p in
               ("target ip:", "target hostname:", "target port:", "start time:", "end time:",
                "server:", "x-frame-options:", "x-xss-protection:", "items checked:",
                "elapsed:", "host(s) tested", "ssl info:")):
            continue
        cve_ids = _CVE_RE.findall(message)
        osvdb_ids = _OSVDB_RE.findall(message)
        sev = "low"
        ml = message.lower()
        if any(k in ml for k in _HIGH_KEYWORDS):
            sev = "medium"
        if cve_ids:
            sev = "high"
        items.append({
            "message": message,
            "cves": cve_ids,
            "osvdb": osvdb_ids,
            "severity": sev,
        })
    return items


def _hosts(ctx: ModuleContext) -> list[str]:
    raw = (ctx.params or {}).get("hosts")
    if isinstance(raw, str):
        if "{{" in raw:
            return []
        return [raw]
    if isinstance(raw, list):
        return [str(h) for h in raw if h]
    s = (ctx.params or {}).get("host")
    return [str(s)] if s else []


def run(ctx: ModuleContext) -> ModuleResult:
    if not tool_available("nikto"):
        return ModuleResult(success=False, error="nikto not installed")
    hosts = _hosts(ctx)
    if not hosts:
        return ModuleResult(success=False, error="no hosts provided")
    if ctx.scope is not None:
        kept, _ = ctx.scope.filter(hosts)
        hosts = kept
    if not hosts:
        return ModuleResult(success=False, error="all hosts dropped by scope")

    # `max_time` (seconds) is passed to nikto's own `-maxtime` flag so
    # nikto self-terminates gracefully and writes its `-output` file
    # before exiting. Without this, a subprocess timeout SIGKILLs nikto
    # mid-scan and the buffered output file ends up empty — losing
    # every check that ran. The subprocess `timeout` is set generously
    # above max_time so it only fires as a safety net.
    max_time = ctx.params.get("max_time")
    if max_time is not None:
        max_time = int(max_time)
    default_timeout = (max_time + 60) if max_time else 300
    timeout = int(ctx.params.get("timeout", default_timeout))
    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    artifacts: list = []
    findings: list[FindingDraft] = []
    summary_bits: list[str] = []

    for host in hosts:
        out_path = ctx.work_dir / f"nikto_{host.replace('.', '_')}_{ts}.txt"
        cmd = ["nikto", "-host", f"https://{host}", "-output", str(out_path)]
        if max_time is not None:
            cmd += ["-maxtime", f"{max_time}s"]
        r = run_cmd(cmd, timeout=timeout)
        artifacts.append(out_path)
        text = out_path.read_text() if out_path.exists() else r.stdout
        items = parse(text)
        json_path = ctx.work_dir / f"nikto_{host.replace('.', '_')}_{ts}.json"
        write_artifact(json_path, json.dumps({"host": host, "items": items}, indent=2))
        artifacts.append(json_path)
        for it in items:
            f = FindingDraft(
                title=f"Nikto: {it['message'][:120]} ({host})",
                severity=it["severity"], cwe=None,
                affected_component=f"https://{host}",
                description=it["message"],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in it["cves"]],
            )
            findings.append(f)
        summary_bits.append(f"{host}: {len(items)} item(s)")

    return ModuleResult(
        success=True,
        artifacts=artifacts,
        findings=findings,
        evidence=[EvidenceRef(path=to_canonical(p), kind="command_output",
                              note="nikto output", host=ctx.worker_host)
                  for p in artifacts if str(p).endswith(".txt")],
        summary="nikto: " + "; ".join(summary_bits),
    )
