"""Findings + assets exporter to XLSX and CSV.

Sheets in the produced workbook:
  - Summary           — engagement metadata + severity counts
  - Findings          — full finding list with status / CVSS / CWE
  - Assets            — master spreadsheet (in_scope, risk tier, ports, techs)
  - CVEs              — every asset+CVE row
  - Risk_Scores       — per-asset risk breakdown (factor → points)
  - Remediation       — one row per finding with remediation text + owner col
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from ...core.paths import to_canonical
from .._engine_callback import get_client
from ..base import EvidenceRef, ModuleContext, ModuleResult

_SEVERITY_FILL = {
    "critical": PatternFill("solid", fgColor="F8D7DA"),
    "high":     PatternFill("solid", fgColor="FFE5B4"),
    "medium":   PatternFill("solid", fgColor="FFF3CD"),
    "low":      PatternFill("solid", fgColor="D1ECF1"),
    "info":     PatternFill("solid", fgColor="EEEEEE"),
}
_HEADER_FONT = Font(bold=True)
_HEADER_FILL = PatternFill("solid", fgColor="E5E7EB")


def _fetch_engagement(client, engagement_id: int) -> dict:
    return {
        "engagement": client.get(f"/engagements/{engagement_id}"),
        "assets": client.get(f"/engagements/{engagement_id}/assets/detail"),
        "findings": client.get(f"/engagements/{engagement_id}/findings"),
    }


def _style_header(ws, ncols: int) -> None:
    for col in range(1, ncols + 1):
        cell = ws.cell(row=1, column=col)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = Alignment(horizontal="left")
    ws.freeze_panes = "A2"


def _write_xlsx(path, payload: dict) -> None:
    wb = Workbook()

    # Summary sheet (replaces the auto-created first sheet)
    ws = wb.active
    ws.title = "Summary"
    eng = payload.get("engagement", {})
    findings = payload.get("findings", [])
    assets = payload.get("assets", [])
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    ws.append(["Engagement", eng.get("client", "")])
    ws.append(["Primary domain", eng.get("primary_domain", "")])
    ws.append(["Status", eng.get("status", "")])
    ws.append(["Created", eng.get("created_at", "")])
    ws.append(["Generated at", datetime.now(UTC).isoformat(timespec="seconds")])
    ws.append([])
    ws.append(["Severity", "Count"])
    _style_header(ws, 2)
    for sev in ("critical", "high", "medium", "low", "info"):
        row_idx = ws.max_row + 1
        ws.append([sev.capitalize(), sev_counts.get(sev, 0)])
        if sev_counts.get(sev, 0):
            ws.cell(row=row_idx, column=1).fill = _SEVERITY_FILL[sev]
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 40

    # Findings
    ws = wb.create_sheet("Findings")
    ws.append([
        "id", "title", "severity", "cvss_score", "cvss_vector",
        "cwe", "status", "affected_component", "remediation",
    ])
    _style_header(ws, 9)
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        row_idx = ws.max_row + 1
        ws.append([
            f.get("id"), f.get("title"), sev, f.get("cvss_score"),
            f.get("cvss_vector"), f.get("cwe"), f.get("status"),
            f.get("affected_component"), f.get("remediation"),
        ])
        fill = _SEVERITY_FILL.get(sev)
        if fill:
            ws.cell(row=row_idx, column=3).fill = fill
    for c, w in zip("ABCDEFGHI", (6, 50, 12, 10, 36, 10, 16, 30, 50), strict=False):
        ws.column_dimensions[c].width = w

    # Assets — master spreadsheet
    ws = wb.create_sheet("Assets")
    ws.append([
        "id", "host", "ip", "env_type", "in_scope", "risk_total",
        "open_ports", "techs", "cve_count",
    ])
    _style_header(ws, 9)
    for a in assets:
        ws.append([
            a["id"], a["host"], a.get("ip"), a.get("env_type"),
            "yes" if a["in_scope"] else "no", a["risk_total"],
            ", ".join(str(p["port"]) for p in a.get("ports", [])),
            ", ".join(f"{t['name']}/{t.get('version', '')}"
                      for t in a.get("techs", [])),
            len(a.get("cves", [])),
        ])

    # CVEs
    ws = wb.create_sheet("CVEs")
    ws.append(["asset_host", "cve_id", "cvss_score", "severity", "summary"])
    _style_header(ws, 5)
    for a in assets:
        for c in a.get("cves", []):
            ws.append([a["host"], c["cve_id"], c.get("cvss_score"),
                       c.get("severity"), c.get("summary")])

    # Risk scores breakdown
    ws = wb.create_sheet("Risk_Scores")
    ws.append(["asset_host", "factor", "points", "note", "tier_running_total"])
    _style_header(ws, 5)
    for a in assets:
        running = 0
        for r in a.get("risk_scores", []):
            running += int(r.get("points", 0) or 0)
            ws.append([a["host"], r.get("factor"), r.get("points"),
                       r.get("note"), running])

    # Remediation roadmap (operator can fill in owner / due date)
    ws = wb.create_sheet("Remediation")
    ws.append([
        "finding_id", "severity", "title", "remediation",
        "owner (fill in)", "due_date (fill in)", "status",
    ])
    _style_header(ws, 7)
    for f in sorted(findings,
                     key=lambda f: ("critical", "high", "medium", "low", "info")
                                    .index((f.get("severity") or "info").lower())):
        sev = (f.get("severity") or "info").lower()
        row_idx = ws.max_row + 1
        ws.append([
            f.get("id"), sev, f.get("title"), f.get("remediation"),
            "", "", f.get("status"),
        ])
        fill = _SEVERITY_FILL.get(sev)
        if fill:
            ws.cell(row=row_idx, column=2).fill = fill
    for c, w in zip("ABCDEFG", (10, 12, 50, 60, 16, 14, 16), strict=False):
        ws.column_dimensions[c].width = w

    wb.save(str(path))


def _write_csv(path, payload: dict) -> None:
    with open(path, "w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["id", "title", "severity", "cvss_score", "cvss_vector", "cwe", "status"])
        for f in payload["findings"]:
            w.writerow([f["id"], f["title"], f["severity"], f.get("cvss_score"),
                        f.get("cvss_vector"), f.get("cwe"), f["status"]])


def export(ctx: ModuleContext) -> ModuleResult:
    engagement_id = (ctx.params or {}).get("engagement_id") or ctx.engagement_id
    if not engagement_id:
        return ModuleResult(success=False, error="missing required param 'engagement_id'")
    client = get_client()
    try:
        payload = _fetch_engagement(client, engagement_id)
    except Exception as e:  # noqa: BLE001
        return ModuleResult(success=False, error=f"engine fetch failed: {e}")

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    xlsx_path = ctx.work_dir / f"findings_{ts}.xlsx"
    csv_path = ctx.work_dir / f"findings_{ts}.csv"
    _write_xlsx(xlsx_path, payload)
    _write_csv(csv_path, payload)

    return ModuleResult(
        success=True,
        artifacts=[xlsx_path, csv_path],
        evidence=[
            EvidenceRef(path=to_canonical(xlsx_path), kind="file",
                        note="findings spreadsheet (xlsx)", host=ctx.worker_host),
            EvidenceRef(path=to_canonical(csv_path), kind="file",
                        note="findings spreadsheet (csv)", host=ctx.worker_host),
        ],
        summary=f"export: {len(payload['findings'])} finding(s), {len(payload['assets'])} asset(s)",
    )
