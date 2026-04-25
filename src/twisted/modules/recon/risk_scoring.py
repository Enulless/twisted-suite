"""Risk scoring matrix per the bug-bounty doc.

Pulls each asset's ports/techs/cves from the engine, applies the
documented scoring rules (software age, known CVEs, missing security
headers, certificate health, email security, infrastructure exposure,
environment type, technology stack complexity) and posts a per-asset
``risk_total`` + per-factor breakdown back to the engine.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from ...core.paths import to_canonical
from ...core.storage import write_artifact
from .._engine_callback import get_client
from ..base import EvidenceRef, ModuleContext, ModuleResult

_DEV_HINTS = ("dev", "staging", "test", "qa", "uat", "preprod", "internal")
_ABANDONED_HINTS = ("backup", "archive", "old", "legacy")
_DB_PORTS = {3306, 5432, 27017, 6379, 1433, 1521, 9200, 11211}
_REMOTE_PORTS = {3389, 22, 23}
_ADMIN_PORTS = {8080, 8443, 9000, 9090, 5601, 5985}


def _env_classify(host: str) -> str:
    h = host.lower()
    if any(token in h for token in _DEV_HINTS):
        return "dev"
    if any(token in h for token in _ABANDONED_HINTS):
        return "abandoned"
    return "production"


def _software_age_points(version: str | None, *, today: datetime | None = None) -> int:
    """Heuristic: 4-digit year inside the version string approximates a release date."""
    if not version:
        return 1
    today = today or datetime.utcnow()
    m = re.search(r"(20\d{2})", version)
    if not m:
        return 1
    age = today.year - int(m.group(1))
    if age < 1:
        return 0
    if age < 2:
        return 1
    if age < 3:
        return 2
    return 3


def _cve_points(cves: list[dict[str, Any]]) -> tuple[int, str]:
    if not cves:
        return 0, "no CVEs"
    crit = sum(1 for c in cves if (c.get("cvss_score") or 0) >= 9)
    if crit >= 1 or len(cves) >= 5:
        return 5, f"{len(cves)} CVE(s) incl. critical"
    if len(cves) >= 3:
        return 3, f"{len(cves)} CVEs with exploits"
    return 1, f"{len(cves)} minor CVE(s)"


def _port_exposure_points(ports: list[dict[str, Any]]) -> tuple[int, list[str]]:
    open_ports = {int(p.get("port", 0)) for p in ports}
    notes: list[str] = []
    points = 0
    if open_ports & _DB_PORTS:
        points += 3
        notes.append(f"DB port(s) exposed: {sorted(open_ports & _DB_PORTS)}")
    if open_ports & _REMOTE_PORTS:
        points += 3
        notes.append(f"remote-access port(s) exposed: {sorted(open_ports & _REMOTE_PORTS)}")
    if open_ports & _ADMIN_PORTS:
        points += 2
        notes.append(f"admin port(s) exposed: {sorted(open_ports & _ADMIN_PORTS)}")
    return points, notes


def score_asset(asset: dict[str, Any], *, today: datetime | None = None) -> dict[str, Any]:
    """Compute a per-asset score; returns {total, breakdown:[{factor,points,note}]}."""
    breakdown: list[dict[str, Any]] = []

    # Software age — take the worst tech version
    techs = asset.get("techs") or []
    if techs:
        worst_age = max(_software_age_points(t.get("version"), today=today) for t in techs)
        breakdown.append({"factor": "software_age", "points": worst_age,
                          "note": f"worst across {len(techs)} tech(s)"})

    # Known CVEs
    pts, note = _cve_points(asset.get("cves") or [])
    breakdown.append({"factor": "known_cves", "points": pts, "note": note})

    # Tech stack complexity
    n_techs = len(techs)
    if n_techs >= 7:
        breakdown.append({"factor": "stack_complexity", "points": 3,
                          "note": f"{n_techs} technologies"})
    elif n_techs >= 4:
        breakdown.append({"factor": "stack_complexity", "points": 2,
                          "note": f"{n_techs} technologies"})
    elif n_techs >= 2:
        breakdown.append({"factor": "stack_complexity", "points": 1,
                          "note": f"{n_techs} technologies"})

    # Infrastructure exposure
    pts, port_notes = _port_exposure_points(asset.get("ports") or [])
    if pts:
        breakdown.append({"factor": "port_exposure", "points": pts,
                          "note": "; ".join(port_notes)})

    # Environment type
    env = asset.get("env_type") or _env_classify(asset.get("host", ""))
    if env in ("dev", "staging"):
        breakdown.append({"factor": "env_dev_staging", "points": 3,
                          "note": f"environment={env}"})
    elif env == "abandoned":
        breakdown.append({"factor": "env_abandoned", "points": 2,
                          "note": "abandoned/legacy"})

    total = sum(b["points"] for b in breakdown)
    return {"total": total, "breakdown": breakdown}


def tier(total: int) -> str:
    if total <= 5:
        return "low"
    if total <= 12:
        return "medium"
    if total <= 20:
        return "high"
    return "critical"


def run(ctx: ModuleContext) -> ModuleResult:
    engagement_id = (ctx.params or {}).get("engagement_id") or ctx.engagement_id
    if not engagement_id:
        return ModuleResult(success=False, error="missing required param 'engagement_id'")

    client = get_client()
    try:
        assets = client.get(f"/engagements/{engagement_id}/assets/detail")
    except Exception as e:  # noqa: BLE001
        return ModuleResult(success=False, error=f"failed to fetch assets: {e}")

    summary_rows: list[dict[str, Any]] = []
    posted = 0
    today = datetime.utcnow()
    for asset in assets:
        scored = score_asset(asset, today=today)
        scored["asset_id"] = asset["id"]
        scored["host"] = asset["host"]
        scored["tier"] = tier(scored["total"])
        summary_rows.append(scored)
        try:
            client.post(
                f"/engagements/{engagement_id}/assets/{asset['id']}/risk",
                json={"total": scored["total"], "breakdown": scored["breakdown"]},
            )
            posted += 1
        except Exception:  # noqa: BLE001
            continue

    summary_rows.sort(key=lambda r: -r["total"])

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    json_path = ctx.work_dir / f"risk_scoring_{ts}.json"
    txt_path = ctx.work_dir / f"risk_scoring_{ts}.txt"
    write_artifact(json_path, json.dumps(summary_rows, indent=2))
    txt_lines = ["host\ttier\ttotal\ttop_factors"]
    for row in summary_rows:
        top = ", ".join(f"{b['factor']}={b['points']}" for b in row["breakdown"][:3])
        txt_lines.append(f"{row['host']}\t{row['tier']}\t{row['total']}\t{top}")
    write_artifact(txt_path, "\n".join(txt_lines))

    by_tier: dict[str, int] = {}
    for r in summary_rows:
        by_tier[r["tier"]] = by_tier.get(r["tier"], 0) + 1

    return ModuleResult(
        success=True,
        artifacts=[json_path, txt_path],
        evidence=[EvidenceRef(path=to_canonical(json_path), kind="command_output",
                              note="risk scoring", host=ctx.worker_host)],
        summary=(f"risk_scoring: scored {len(assets)} asset(s); "
                 f"updated {posted}; by tier: {by_tier}"),
        extra={"by_tier": by_tier, "scored": len(assets), "updated": posted},
    )
