"""WHOIS registrar lookup wrapper."""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult


def _root_domain(host: str) -> str:
    parts = (host or "").strip().lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _parse(blob: str) -> dict[str, str | list[str]]:
    out: dict[str, str | list[str]] = {}
    for line in blob.splitlines():
        if ":" not in line or line.lstrip().startswith(("%", "#", ";")):
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if not k or not v:
            continue
        if k in out:
            existing = out[k]
            if isinstance(existing, list):
                existing.append(v)
            else:
                out[k] = [existing, v]
        else:
            out[k] = v
    return out


def run(ctx: ModuleContext) -> ModuleResult:
    host = (ctx.params or {}).get("host") or (ctx.params or {}).get("domain")
    if not host:
        return ModuleResult(success=False, error="missing required param 'host' or 'domain'")
    if not tool_available("whois"):
        return ModuleResult(success=False, error="whois not installed")

    domain = _root_domain(host)
    r = run_cmd(["whois", domain], timeout=int(ctx.params.get("timeout", 15)))
    if r.error and not r.stdout:
        return ModuleResult(success=False, error=r.error or "whois failed", summary=str(r.error))

    parsed = _parse(r.stdout)
    expiry = ""
    for k in ("registry expiry date", "expiration date", "expires", "expiry date"):
        if k in parsed and isinstance(parsed[k], str):
            expiry = parsed[k]
            break

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    safe = domain.replace(".", "_")
    raw_path = ctx.work_dir / f"whois_{safe}_{ts}.txt"
    json_path = ctx.work_dir / f"whois_{safe}_{ts}.json"
    write_artifact(raw_path, r.stdout)

    payload = {
        "tool": "whois",
        "domain": domain,
        "queried_at": ctx.timestamp.isoformat(),
        "parsed": parsed,
    }
    write_artifact(json_path, json.dumps(payload, indent=2))

    return ModuleResult(
        success=True,
        artifacts=[raw_path, json_path],
        evidence=[
            EvidenceRef(path=to_canonical(raw_path), kind="command_output",
                        note="whois raw", host=ctx.worker_host),
        ],
        summary=f"whois {domain}: {len(parsed)} field(s); expiry={expiry or 'n/a'}",
        extra={"expiry": expiry},
    )
