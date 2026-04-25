"""ApacheBench (`ab`) baseline runner."""

from __future__ import annotations

import json
import re

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult

_PARSERS = [
    ("requests_per_sec", re.compile(r"Requests per second:\s*([\d.]+)")),
    ("mean_ms",          re.compile(r"Time per request:\s*([\d.]+)\s*\[ms\]\s*\(mean\)")),
    ("transfer_kbs",     re.compile(r"Transfer rate:\s*([\d.]+)\s*\[Kbytes/sec\]")),
    ("failed_requests",  re.compile(r"Failed requests:\s*(\d+)")),
    ("non_2xx",          re.compile(r"Non-2xx responses:\s*(\d+)")),
    ("p50_ms",           re.compile(r"^\s*50%\s+(\d+)\s*$", re.MULTILINE)),
    ("p95_ms",           re.compile(r"^\s*95%\s+(\d+)\s*$", re.MULTILINE)),
    ("p99_ms",           re.compile(r"^\s*99%\s+(\d+)\s*$", re.MULTILINE)),
    ("complete",         re.compile(r"Complete requests:\s*(\d+)")),
]


def parse_ab(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for key, pat in _PARSERS:
        m = pat.search(text)
        if m:
            try:
                out[key] = float(m.group(1))
            except ValueError:
                continue
    if "complete" in out and "failed_requests" in out and out["complete"] > 0:
        out["error_rate"] = (out["failed_requests"] + out.get("non_2xx", 0)) / out["complete"]
    return out


def _normalise_url(url: str) -> str:
    if "://" not in url:
        url = f"https://{url}"
    if not url.endswith("/"):
        url += "/"
    return url


def run(ctx: ModuleContext) -> ModuleResult:
    url = (ctx.params or {}).get("url") or (ctx.params or {}).get("host")
    if not url:
        return ModuleResult(success=False, error="missing required param 'url'")
    if not tool_available("ab"):
        return ModuleResult(success=False, error="ab (apache2-utils) not installed")
    requests = int((ctx.params or {}).get("requests", 100))
    concurrency = int((ctx.params or {}).get("concurrency", 5))
    timeout = int((ctx.params or {}).get("timeout", 120))
    target = _normalise_url(url)

    cmd = ["ab", "-n", str(requests), "-c", str(concurrency), target]
    r = run_cmd(cmd, timeout=timeout)
    if not r.ok and not r.stdout:
        return ModuleResult(success=False, error=r.error or f"ab failed: rc={r.returncode}")

    parsed = parse_ab(r.stdout)
    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    base = f"ab_{requests}_{concurrency}_{ts}"
    txt_path = ctx.work_dir / f"{base}.txt"
    json_path = ctx.work_dir / f"{base}.json"
    write_artifact(txt_path, r.stdout)
    write_artifact(json_path, json.dumps({
        "tool": "ab", "url": target, "requests": requests,
        "concurrency": concurrency, "metrics": parsed,
    }, indent=2))

    summary = (
        f"ab {target} n={requests} c={concurrency}: "
        f"rps={parsed.get('requests_per_sec', '?')} "
        f"mean={parsed.get('mean_ms', '?')}ms "
        f"p99={parsed.get('p99_ms', '?')}ms "
        f"errors={parsed.get('error_rate', 0):.3%}"
    )
    return ModuleResult(
        success=True,
        artifacts=[txt_path, json_path],
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="ab baseline", host=ctx.worker_host)],
        summary=summary,
        extra={"metrics": parsed},
    )
