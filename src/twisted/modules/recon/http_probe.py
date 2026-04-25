"""HTTP/HTTPS probe.

Generalised port of recon_ovh.py's ``http_probe``. Detects scheme,
status, redirect chain, server header, page title, and a small set of
header-based technology hints. Writes both a per-host JSON file and a
combined summary text file.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests
import urllib3

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from ..base import AssetUpdate, EvidenceRef, ModuleContext, ModuleResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_one(host: str, *, timeout: int = 10, user_agent: str = "TwistedRecon/0.1",
              session: requests.Session | None = None) -> dict[str, Any]:
    sess = session or requests.Session()
    result: dict[str, Any] = {
        "host": host,
        "scheme_used": None,
        "status": None,
        "title": None,
        "server": None,
        "redirect": None,
        "headers": {},
        "techs": [],
        "errors": {},
    }
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = sess.get(
                url, timeout=timeout, allow_redirects=True, verify=False,
                headers={"User-Agent": user_agent},
            )
        except Exception as e:  # noqa: BLE001 - probing inherently noisy
            result["errors"][scheme] = str(e)[:200]
            continue
        result["scheme_used"] = scheme
        result["status"] = r.status_code
        result["headers"] = dict(r.headers)
        result["server"] = r.headers.get("Server", "")
        m = _TITLE_RE.search(r.text)
        if m:
            result["title"] = m.group(1).strip()[:160]
        if r.history:
            result["redirect"] = r.url
        techs: list[str] = []
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        if "x-powered-by" in hdrs:
            techs.append(f"X-Powered-By: {hdrs['x-powered-by']}")
        if "x-generator" in hdrs:
            techs.append(f"Generator: {hdrs['x-generator']}")
        if "cf-ray" in hdrs:
            techs.append("Cloudflare")
        if any(k.startswith("x-amz-") for k in hdrs):
            techs.append("AWS")
        if "x-drupal-cache" in hdrs:
            techs.append("Drupal")
        result["techs"] = techs
        break
    return result


def run(ctx: ModuleContext) -> ModuleResult:
    hosts: list[str] = (ctx.params or {}).get("hosts") or []
    single_host = (ctx.params or {}).get("host")
    if single_host and single_host not in hosts:
        hosts = [single_host, *hosts]
    if not hosts:
        return ModuleResult(success=False, error="missing required param 'host' or 'hosts'")

    if ctx.scope is not None:
        kept, _dropped = ctx.scope.filter(hosts)
        hosts = kept
    if not hosts:
        return ModuleResult(success=False, error="no in-scope hosts to probe")

    timeout = int(ctx.params.get("timeout", 10))
    sess = requests.Session()
    results: list[dict[str, Any]] = []
    summary_lines: list[str] = []
    for h in hosts:
        info = probe_one(h, timeout=timeout, session=sess)
        results.append(info)
        line = f"{h}\t{info.get('scheme_used') or '-'}\t{info.get('status') or '-'}"
        if info.get("title"):
            line += f"\ttitle={info['title'][:60]}"
        if info.get("server"):
            line += f"\tserver={info['server']}"
        summary_lines.append(line)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"http_probe_{ts}.json"
    txt_path = ctx.work_dir / f"http_probe_{ts}.txt"
    write_artifact(json_path, json.dumps(results, indent=2))
    write_artifact(txt_path, "\n".join(["host\tscheme\tstatus\textras", *summary_lines]))

    assets: list[AssetUpdate] = []
    for info in results:
        if info.get("status") is not None:
            assets.append(AssetUpdate(host=info["host"], source="http_probe"))

    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        assets=assets,
        evidence=[
            EvidenceRef(path=to_canonical(json_path), kind="command_output",
                        note="http_probe JSON dump", host=ctx.worker_host),
        ],
        summary=f"http_probe: {len(hosts)} host(s) probed, {sum(1 for r in results if r.get('status'))} responded",
    )
