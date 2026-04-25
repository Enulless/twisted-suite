"""wrk-based escalating concurrency runner with auto-stop on saturation."""

from __future__ import annotations

import json
import re

from ...core.paths import to_canonical
from ...core.runner import run_cmd, tool_available
from ...core.storage import write_artifact
from ..base import EvidenceRef, ModuleContext, ModuleResult

_WRK_PARSERS = [
    ("requests_per_sec", re.compile(r"Requests/sec:\s*([\d.]+)")),
    ("transfer_per_sec", re.compile(r"Transfer/sec:\s*([\d.]+\w+)")),
    ("avg_latency",      re.compile(r"^\s*Latency\s+([\d.]+\w+)", re.MULTILINE)),
    ("p99_latency",      re.compile(r"^\s*99%\s+([\d.]+\w+)", re.MULTILINE)),
    ("requests_total",   re.compile(r"^\s*(\d+)\s+requests in", re.MULTILINE)),
    ("non_2xx",          re.compile(r"Non-2xx or 3xx responses:\s*(\d+)")),
    ("socket_errors",    re.compile(r"Socket errors:.*?total\s+(\d+)", re.DOTALL)),
]


def parse_wrk(text: str) -> dict[str, str | float]:
    out: dict[str, str | float] = {}
    for key, pat in _WRK_PARSERS:
        m = pat.search(text)
        if not m:
            continue
        val = m.group(1)
        try:
            out[key] = float(val)
        except ValueError:
            out[key] = val
    if "requests_total" in out and "non_2xx" in out:
        try:
            total = float(out["requests_total"])
            errors = float(out["non_2xx"])
            out["error_rate"] = errors / total if total > 0 else 0.0
        except (TypeError, ValueError):
            pass
    return out


def _normalise_url(url: str) -> str:
    if "://" not in url:
        url = f"https://{url}"
    return url


def run(ctx: ModuleContext) -> ModuleResult:
    url = (ctx.params or {}).get("url") or (ctx.params or {}).get("host")
    if not url:
        return ModuleResult(success=False, error="missing required param 'url'")
    if not tool_available("wrk"):
        return ModuleResult(success=False, error="wrk not installed")

    duration = int((ctx.params or {}).get("duration", 30))
    threads = int((ctx.params or {}).get("threads", 4))
    rounds = list((ctx.params or {}).get("rounds") or [50, 100, 250, 500])
    target = _normalise_url(url)

    artifacts = []
    rounds_data: list[dict] = []
    saturation: int | None = None
    saturation_reason: str | None = None
    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")

    for connections in rounds:
        cmd = ["wrk", "-t", str(threads), "-c", str(connections),
               "-d", f"{duration}s", "--latency", target]
        r = run_cmd(cmd, timeout=duration + 60)
        out = r.stdout or ""
        parsed = parse_wrk(out)
        round_path = ctx.work_dir / f"wrk_c{connections}_{ts}.txt"
        write_artifact(round_path, out)
        artifacts.append(round_path)
        rounds_data.append({
            "connections": connections, "duration": duration,
            "metrics": parsed,
        })
        # Saturation heuristics from the procedure doc
        err = parsed.get("error_rate", 0) or 0
        if isinstance(err, (int, float)) and err > 0.5:
            saturation = connections
            saturation_reason = f"error rate {err:.0%} > 50%"
            break
        sock_err = parsed.get("socket_errors", 0) or 0
        if isinstance(sock_err, (int, float)) and sock_err > 0:
            saturation = connections
            saturation_reason = f"socket errors observed at c={connections}"
            break

    json_path = ctx.work_dir / f"wrk_summary_{ts}.json"
    summary_payload = {
        "tool": "wrk", "url": target, "rounds": rounds_data,
        "saturation_concurrency": saturation,
        "saturation_reason": saturation_reason,
    }
    write_artifact(json_path, json.dumps(summary_payload, indent=2))
    artifacts.append(json_path)

    summary = (
        f"wrk: {len(rounds_data)} round(s) up to c={rounds[-1]}; "
        f"saturation={saturation or 'not reached'}"
        f"{f' ({saturation_reason})' if saturation_reason else ''}"
    )
    return ModuleResult(
        success=True,
        artifacts=artifacts,
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="wrk escalating", host=ctx.worker_host)],
        summary=summary,
        extra={"saturation_concurrency": saturation, "rounds": len(rounds_data)},
    )
