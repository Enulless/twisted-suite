"""Nmap port scan wrappers.

Two entry points: ``scan_top_ports`` (fast, the procedure's curated list)
and ``scan_full`` (-p- 65k sweep, intended for critical-tier targets only).
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import AssetUpdate, EvidenceRef, ModuleContext, ModuleResult

TOP_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,3306,3389,5432,5900,5985,6379,8080,8443,8888,9000,9200,11211,27017"


_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.+?)(?:\s+(.+))?$")


def parse_nmap_text(text: str) -> dict[str, list[dict[str, Any]]]:
    """Parse standard nmap text output into per-host port lists."""
    hosts: dict[str, list[dict[str, Any]]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = re.match(r"^Nmap scan report for (\S+).*", line)
        if m:
            current = m.group(1)
            hosts[current] = []
            continue
        if current is None:
            continue
        if not (line.startswith(("22/tcp", "21/tcp")) or "/tcp " in line or "/udp " in line):
            # Try to match generic "<port>/<proto> <state> <service> [version]"
            mp = _LINE_RE.match(line.strip())
            if mp:
                port, proto, state, service, version = mp.groups()
                if state == "open":
                    hosts[current].append({
                        "port": int(port), "proto": proto,
                        "service": service, "version": (version or "").strip(),
                    })
            continue
        mp = _LINE_RE.match(line.strip())
        if mp:
            port, proto, state, service, version = mp.groups()
            if state == "open":
                hosts[current].append({
                    "port": int(port), "proto": proto,
                    "service": service, "version": (version or "").strip(),
                })
    return hosts


def _hosts(ctx: ModuleContext) -> list[str]:
    raw = (ctx.params or {}).get("hosts")
    if isinstance(raw, str):
        # Engine may have left the placeholder unrendered; treat as empty.
        if "{{" in raw:
            return []
        return [raw]
    if isinstance(raw, list):
        return [str(h) for h in raw if h]
    single = (ctx.params or {}).get("host")
    return [str(single)] if single else []


def _scan(ctx: ModuleContext, *, port_spec: str, label: str, timeout: int = 600) -> ModuleResult:
    if not tool_available("nmap"):
        return ModuleResult(success=False, error="nmap not installed")
    hosts = _hosts(ctx)
    if not hosts:
        return ModuleResult(success=False, error="no hosts to scan")
    if ctx.scope is not None:
        kept, _ = ctx.scope.filter(hosts)
        hosts = kept
    if not hosts:
        return ModuleResult(success=False, error="all hosts dropped by scope filter")

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    outputs_base = ctx.work_dir / f"nmap_{label}_{ts}"
    cmd = ["nmap", "-T3", "--open", "-sV", "-p", port_spec, "-oA", str(outputs_base), *hosts]
    r = run_cmd(cmd, timeout=timeout)
    if not r.ok and not (outputs_base.with_suffix(".nmap")).exists():
        return ModuleResult(success=False, error=r.error or f"nmap exit {r.returncode}")

    text_path = outputs_base.with_suffix(".nmap")
    parsed = parse_nmap_text(text_path.read_text() if text_path.exists() else r.stdout)
    json_path = ctx.work_dir / f"nmap_{label}_{ts}.json"
    write_artifact(json_path, json.dumps(parsed, indent=2))

    assets: list[AssetUpdate] = []
    for host, ports in parsed.items():
        if ports:
            assets.append(AssetUpdate(host=host, source=f"nmap_{label}",
                                       extra={"open_ports": [p["port"] for p in ports]}))

    summary_lines = [f"nmap {label}: {len(hosts)} host(s) scanned"]
    for host, ports in parsed.items():
        for p in ports:
            summary_lines.append(f"  {host}:{p['port']}/{p['proto']} {p['service']} {p['version']}")

    return ModuleResult(
        success=True,
        artifacts=[json_path, text_path] if text_path.exists() else [json_path],
        assets=assets,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note=f"nmap {label}", host=ctx.worker_host)],
        summary="\n".join(summary_lines),
        extra={"hosts_scanned": len(hosts), "open_port_count": sum(len(v) for v in parsed.values())},
    )


def scan_top_ports(ctx: ModuleContext) -> ModuleResult:
    return _scan(ctx, port_spec=TOP_PORTS, label="top", timeout=600)


def scan_full(ctx: ModuleContext) -> ModuleResult:
    return _scan(ctx, port_spec="-", label="full", timeout=3600)
