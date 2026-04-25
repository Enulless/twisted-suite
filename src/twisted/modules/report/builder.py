"""Report builder — produces the final Cover/Exec/Findings document.

Pulls the engagement, assets, and findings from the engine API, builds
a ``ReportData`` (from core.reporting), renders markdown + HTML, and
optionally PDF (when WeasyPrint is installed). Each rendered file is
returned as evidence so the Finalize flow can promote them to OneDrive.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ...core.paths import to_canonical
from ...core.reporting import (
    FindingSummary,
    ReportData,
    render_executive_html,
    render_html,
    render_markdown,
)
from ...core.storage import write_artifact
from .._engine_callback import get_client
from ..base import EvidenceRef, ModuleContext, ModuleResult


def _summary_from(api_finding: dict) -> FindingSummary:
    return FindingSummary(
        id=api_finding.get("id"),
        title=api_finding.get("title", ""),
        severity=api_finding.get("severity", "info"),
        cvss_score=api_finding.get("cvss_score"),
        cvss_vector=api_finding.get("cvss_vector"),
        cwe=api_finding.get("cwe"),
        affected_component=None, description=None, root_cause=None,
        repro_steps=None, impact=None, remediation=None,
    )


def build(ctx: ModuleContext) -> ModuleResult:
    engagement_id = (ctx.params or {}).get("engagement_id") or ctx.engagement_id
    if not engagement_id:
        return ModuleResult(success=False, error="missing required param 'engagement_id'")
    formats = (ctx.params or {}).get("formats") or ["html", "markdown"]
    if isinstance(formats, str):
        formats = [s.strip() for s in formats.split(",") if s.strip()]

    client = get_client()
    try:
        engagement = client.get(f"/engagements/{engagement_id}")
        assets = client.get(f"/engagements/{engagement_id}/assets")
        findings = client.get(f"/engagements/{engagement_id}/findings")
        scope_rows = client.get(f"/engagements/{engagement_id}/scope")
    except Exception as e:  # noqa: BLE001
        return ModuleResult(success=False, error=f"engine fetch failed: {e}")

    scope_summary = "\n".join(f"{r['kind']}: {r['pattern']}" for r in scope_rows)
    started = datetime.fromisoformat(engagement["created_at"].replace("Z", "+00:00")) \
        if engagement.get("created_at") else datetime.now(UTC)

    data = ReportData(
        client=engagement["client"],
        primary_domain=engagement.get("primary_domain"),
        engagement_started=started,
        engagement_ended=datetime.now(UTC),
        scope_summary=scope_summary,
        asset_count=len(assets),
        findings=[_summary_from(f) for f in findings],
    )

    ts = ctx.timestamp.strftime("%Y%m%d_%H%M%S")
    artifacts = []
    evidence = []

    if "markdown" in formats or "md" in formats:
        md = render_markdown(data)
        p = ctx.work_dir / f"report_{ts}.md"
        write_artifact(p, md)
        artifacts.append(p)
        evidence.append(EvidenceRef(path=to_canonical(p), kind="file",
                                     note="full report (markdown)", host=ctx.worker_host))

    if "html" in formats:
        html = render_html(data)
        p = ctx.work_dir / f"report_{ts}.html"
        write_artifact(p, html)
        artifacts.append(p)
        evidence.append(EvidenceRef(path=to_canonical(p), kind="file",
                                     note="full report (html)", host=ctx.worker_host))

    if "executive" in formats or "exec" in formats:
        exec_html = render_executive_html(data)
        p = ctx.work_dir / f"executive_summary_{ts}.html"
        write_artifact(p, exec_html)
        artifacts.append(p)
        evidence.append(EvidenceRef(path=to_canonical(p), kind="file",
                                     note="executive one-pager (html)",
                                     host=ctx.worker_host))

    if "pdf" in formats or "executive_pdf" in formats:
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError:
            return ModuleResult(
                success=False,
                error="weasyprint not installed (pip install 'twisted-suite[report]')",
            )
        if "pdf" in formats:
            try:
                html_str = render_html(data)
                p = ctx.work_dir / f"report_{ts}.pdf"
                HTML(string=html_str).write_pdf(str(p))
                artifacts.append(p)
                evidence.append(EvidenceRef(path=to_canonical(p), kind="file",
                                             note="full report (pdf)",
                                             host=ctx.worker_host))
            except Exception as e:  # noqa: BLE001
                return ModuleResult(success=False,
                                    error=f"weasyprint full-report failed: {e}")
        if "executive_pdf" in formats:
            try:
                exec_str = render_executive_html(data)
                p = ctx.work_dir / f"executive_summary_{ts}.pdf"
                HTML(string=exec_str).write_pdf(str(p))
                artifacts.append(p)
                evidence.append(EvidenceRef(path=to_canonical(p), kind="file",
                                             note="executive one-pager (pdf)",
                                             host=ctx.worker_host))
            except Exception as e:  # noqa: BLE001
                return ModuleResult(success=False,
                                    error=f"weasyprint exec-summary failed: {e}")

    return ModuleResult(
        success=True,
        artifacts=artifacts,
        evidence=evidence,
        summary=(f"report: {len(findings)} finding(s) across {len(assets)} asset(s); "
                 f"formats={formats}"),
        extra={"finding_count": len(findings), "asset_count": len(assets)},
    )
