"""NVD CVE cross-reference module.

Fetches the engagement's assets+technologies from the engine, queries the
NVD REST API for each tech+version, and posts back CVE rows for each
asset. Honours simple caching via on-disk artifact + a tight rate limit
(NVD free tier allows ~5 req/30 s without an API key).
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from .._engine_callback import get_client
from ..base import EvidenceRef, ModuleContext, ModuleResult

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "TwistedRecon/0.1 NVD-lookup"
DEFAULT_RATE_LIMIT = 6  # seconds between requests when no API key


def _query_nvd(keyword: str, *, api_key: str | None = None,
               session: requests.Session | None = None,
               timeout: int = 20) -> list[dict[str, Any]]:
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    r = sess.get(NVD_URL, params={"keywordSearch": keyword,
                                  "keywordExactMatch": "", "resultsPerPage": 50},
                 headers=headers, timeout=timeout)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    body = r.json()
    return body.get("vulnerabilities", []) or []


def _flatten(vuln: dict[str, Any]) -> dict[str, Any]:
    cve = vuln.get("cve", {})
    metrics = cve.get("metrics", {}) or {}
    cvss_score: float | None = None
    severity: str | None = None
    for label in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(label) or []
        if rows:
            data = (rows[0].get("cvssData") or {})
            cvss_score = data.get("baseScore")
            severity = data.get("baseSeverity") or rows[0].get("baseSeverity")
            break
    descriptions = cve.get("descriptions") or []
    summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
    return {
        "cve_id": cve.get("id"),
        "cvss_score": cvss_score,
        "severity": severity,
        "summary": summary,
        "references": [r.get("url") for r in (cve.get("references") or []) if r.get("url")],
    }


def run(ctx: ModuleContext) -> ModuleResult:
    engagement_id = (ctx.params or {}).get("engagement_id") or ctx.engagement_id
    if not engagement_id:
        return ModuleResult(success=False, error="missing required param 'engagement_id'")
    api_key = (ctx.params or {}).get("api_key") or None
    rate_sleep = float((ctx.params or {}).get("rate_sleep", DEFAULT_RATE_LIMIT))
    max_techs = int((ctx.params or {}).get("max_techs", 25))

    client = get_client()
    try:
        assets = client.get(f"/engagements/{engagement_id}/assets/detail")
    except Exception as e:  # noqa: BLE001
        return ModuleResult(success=False, error=f"failed to fetch assets: {e}")
    if not assets:
        return ModuleResult(success=True, summary="nvd_lookup: no assets to evaluate")

    # Build a deduped lookup map: (tech_name, version) -> [(asset_id, host)]
    tech_targets: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for a in assets:
        for t in a.get("techs", []):
            name = (t.get("name") or "").strip()
            ver = (t.get("version") or "").strip()
            if not name or not ver:
                continue
            tech_targets.setdefault((name, ver), []).append((a["id"], a["host"]))

    if not tech_targets:
        return ModuleResult(success=True,
                            summary="nvd_lookup: no asset technologies recorded yet")

    targets = list(tech_targets.items())[:max_techs]

    sess = requests.Session()
    all_results: list[dict] = []
    cves_per_asset: dict[int, list[dict]] = {}
    for (name, ver), assets_for in targets:
        keyword = f"{name} {ver}"
        try:
            raw = _query_nvd(keyword, api_key=api_key, session=sess)
        except requests.RequestException as e:
            all_results.append({"keyword": keyword, "error": str(e)[:200]})
            time.sleep(rate_sleep)
            continue
        flat = [_flatten(v) for v in raw if v]
        for entry in flat:
            for asset_id, _host in assets_for:
                cves_per_asset.setdefault(asset_id, []).append(entry)
        all_results.append({"keyword": keyword, "matches": len(flat), "cves": flat})
        if not api_key:
            time.sleep(rate_sleep)

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"nvd_lookup_{ts}.json"
    write_artifact(json_path, json.dumps(all_results, indent=2))

    posted = 0
    for asset_id, cves in cves_per_asset.items():
        try:
            client.post(f"/engagements/{engagement_id}/assets/{asset_id}/cves", json=cves)
            posted += len(cves)
        except Exception:  # noqa: BLE001
            continue

    return ModuleResult(
        success=True,
        artifacts=[json_path],
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="NVD lookup raw + matches", host=ctx.worker_host)],
        summary=(f"nvd_lookup: queried {len(targets)} tech+version pair(s); "
                 f"attached {posted} CVE row(s) across {len(cves_per_asset)} asset(s)"),
        extra={"queries": len(targets), "cve_attachments": posted},
    )
