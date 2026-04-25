"""DNS record enumeration via the system ``dig`` binary.

Generalised port of recon_ovh.py's ``dns_lookup``: queries A, AAAA, CNAME,
MX, TXT, NS, SOA records and writes both .txt and .json artifacts.
"""

from __future__ import annotations

import json
from typing import Any

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult

DEFAULT_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")
DEFAULT_RESOLVER = "8.8.8.8"


def _dig(host: str, rtype: str, *, resolver: str = DEFAULT_RESOLVER, timeout: int = 10) -> list[str]:
    r = run_cmd(["dig", f"@{resolver}", "+short", rtype, host], timeout=timeout)
    if not r.ok:
        return []
    out: list[str] = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        out.append(line)
    return out


def lookup(host: str, record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
           resolver: str = DEFAULT_RESOLVER, timeout: int = 10) -> dict[str, list[str]]:
    """Run dig for each record type and return a mapping."""
    results: dict[str, list[str]] = {}
    for rtype in record_types:
        values = _dig(host, rtype, resolver=resolver, timeout=timeout)
        if values:
            results[rtype] = values
    return results


def run(ctx: ModuleContext) -> ModuleResult:
    host = (ctx.params or {}).get("host") or (ctx.params or {}).get("domain")
    if not host:
        return ModuleResult(success=False, error="missing required param 'host' or 'domain'")
    if not tool_available("dig"):
        return ModuleResult(
            success=False,
            error="dig not installed (apt install dnsutils on Debian/Ubuntu)",
        )

    rtypes = tuple(ctx.params.get("record_types") or DEFAULT_RECORD_TYPES)
    resolver = ctx.params.get("resolver", DEFAULT_RESOLVER)
    data = lookup(host, record_types=rtypes, resolver=resolver)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    safe_host = host.replace(".", "_")
    json_path = ctx.work_dir / f"dns_{safe_host}_{ts}.json"
    txt_path = ctx.work_dir / f"dns_{safe_host}_{ts}.txt"

    payload: dict[str, Any] = {
        "tool": "dig",
        "host": host,
        "resolver": resolver,
        "queried_at": ctx.timestamp.isoformat(),
        "records": data,
    }
    write_artifact(json_path, json.dumps(payload, indent=2))

    txt_lines = [f"dig @{resolver} {host} (record types: {', '.join(rtypes)})", ""]
    for rtype, values in data.items():
        txt_lines.append(f"── {rtype} ──")
        txt_lines.extend(values)
        txt_lines.append("")
    write_artifact(txt_path, "\n".join(txt_lines))

    summary = f"dig {host}: {sum(len(v) for v in data.values())} records across {len(data)} type(s)"
    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        evidence=[
            EvidenceRef(path=to_canonical(json_path), kind="command_output",
                        note="dig JSON dump", host=ctx.worker_host),
        ],
        summary=summary,
        extra={"record_count": sum(len(v) for v in data.values())},
    )
