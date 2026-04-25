"""Targeted endpoint stress for high-cost WordPress endpoints."""

from __future__ import annotations

import json

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult
from .ab_baseline import parse_ab

_ENDPOINTS = (
    ("login",      "wp-login.php"),
    ("admin_ajax", "wp-admin/admin-ajax.php"),
    ("search",     "?s=test"),
    ("xmlrpc",     "xmlrpc.php"),
)


def _normalise(url: str) -> str:
    if "://" not in url:
        url = f"https://{url}"
    return url.rstrip("/") + "/"


def run(ctx: ModuleContext) -> ModuleResult:
    url = (ctx.params or {}).get("url") or (ctx.params or {}).get("host")
    if not url:
        return ModuleResult(success=False, error="missing required param 'url'")
    if not tool_available("ab"):
        return ModuleResult(success=False, error="ab not installed")
    requests = int((ctx.params or {}).get("requests", 500))
    concurrency = int((ctx.params or {}).get("concurrency", 25))
    timeout = int((ctx.params or {}).get("timeout", 180))
    base_url = _normalise(url)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    artifacts = []
    rows: list[dict] = []

    for label, suffix in _ENDPOINTS:
        target = base_url + suffix
        r = run_cmd(["ab", "-n", str(requests), "-c", str(concurrency), target],
                    timeout=timeout)
        text = r.stdout or ""
        round_path = ctx.work_dir / f"endpoint_{label}_{ts}.txt"
        write_artifact(round_path, text)
        artifacts.append(round_path)
        rows.append({"endpoint": label, "url": target, "metrics": parse_ab(text),
                     "exit_code": r.returncode})

    json_path = ctx.work_dir / f"endpoint_stress_{ts}.json"
    write_artifact(json_path, json.dumps({"url": base_url, "rounds": rows}, indent=2))
    artifacts.append(json_path)

    return ModuleResult(
        success=True,
        artifacts=artifacts,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="endpoint stress", host=ctx.worker_host)],
        summary=f"endpoint_stress: {len(rows)} endpoint(s) at n={requests} c={concurrency}",
        extra={"endpoints": [r["endpoint"] for r in rows]},
    )
