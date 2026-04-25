"""Subdomain aggregator wrappers (subfinder, assetfinder, amass)."""

from __future__ import annotations

import json
from collections.abc import Iterable

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import AssetUpdate, EvidenceRef, ModuleContext, ModuleResult


def _filter_to_domain(lines: Iterable[str], domain: str) -> set[str]:
    suffix = domain.lower().rstrip(".")
    out: set[str] = set()
    for raw in lines:
        h = raw.strip().lower().lstrip("*.").rstrip(".")
        if not h or " " in h:
            continue
        if h == suffix or h.endswith("." + suffix):
            out.add(h)
    return out


def _wrap(ctx: ModuleContext, *, tool: str, cmd: list[str], timeout: int = 120,
          source_label: str | None = None) -> ModuleResult:
    domain = (ctx.params or {}).get("domain")
    if not domain:
        return ModuleResult(success=False, error="missing required param 'domain'")
    if not tool_available(tool):
        return ModuleResult(success=False, error=f"{tool} not installed")
    r = run_cmd(cmd, timeout=timeout)
    if not r.ok and not r.stdout:
        return ModuleResult(success=False, error=r.error or f"{tool} exited {r.returncode}")
    found = _filter_to_domain(r.stdout.splitlines(), domain)
    in_scope = set(found)
    dropped: set[str] = set()
    if ctx.scope is not None:
        kept, drops = ctx.scope.filter(found)
        in_scope, dropped = set(kept), set(drops)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    label = source_label or tool
    safe = domain.replace(".", "_")
    json_path = ctx.work_dir / f"{label}_{safe}_{ts}.json"
    txt_path = ctx.work_dir / f"{label}_{safe}_{ts}.txt"
    payload = {
        "tool": tool, "domain": domain, "queried_at": ctx.timestamp.isoformat(),
        "raw_count": len(found), "in_scope": sorted(in_scope), "dropped_oos": sorted(dropped),
    }
    write_artifact(json_path, json.dumps(payload, indent=2))
    write_artifact(txt_path, "\n".join(sorted(in_scope)))

    assets = [AssetUpdate(host=h, source=label) for h in sorted(in_scope)]
    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        assets=assets,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note=f"{label} JSON dump", host=ctx.worker_host)],
        summary=f"{label}: {len(found)} unique sub(s) for {domain}; {len(in_scope)} in scope, {len(dropped)} OOS",
        extra={"raw_count": len(found)},
    )


def subfinder(ctx: ModuleContext) -> ModuleResult:
    domain = (ctx.params or {}).get("domain")
    return _wrap(ctx, tool="subfinder",
                 cmd=["subfinder", "-d", str(domain), "-silent", "-timeout", "30"],
                 source_label="subfinder")


def assetfinder(ctx: ModuleContext) -> ModuleResult:
    domain = (ctx.params or {}).get("domain")
    return _wrap(ctx, tool="assetfinder",
                 cmd=["assetfinder", "--subs-only", str(domain)],
                 source_label="assetfinder")


def amass_passive(ctx: ModuleContext) -> ModuleResult:
    domain = (ctx.params or {}).get("domain")
    return _wrap(ctx, tool="amass",
                 cmd=["amass", "enum", "-passive", "-d", str(domain), "-timeout", "60"],
                 timeout=180, source_label="amass_passive")


def sublist3r(ctx: ModuleContext) -> ModuleResult:
    """sublist3r is a Python tool that prints to stdout when called via -o /dev/stdout."""
    domain = (ctx.params or {}).get("domain")
    return _wrap(ctx, tool="sublist3r",
                 cmd=["sublist3r", "-d", str(domain), "-o", "/dev/stdout"],
                 source_label="sublist3r")
