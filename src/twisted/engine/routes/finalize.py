"""OneDrive finalize endpoints.

POST /engagements/{id}/findings/{fid}/finalize  → archive evidence,
                                                  stamp finalized_at,
                                                  flip status to REPORTED.
POST /engagements/{id}/finalize-report          → copy report files
                                                  into <archive>/reports/.
GET  /engagements/{id}/archive-status           → tells the caller
                                                  whether archive is
                                                  configured + the
                                                  resolved archive root.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from ...core import models as m
from ...core.db import session_scope
from ...core.finalize import (
    archive_paths_for,
    finalize_evidence_for_finding,
    finalize_report,
    now_utc,
)
from ..auth import require_token_dep

router = APIRouter(tags=["finalize"], dependencies=[require_token_dep])


class FinalizeFindingResponse(BaseModel):
    success: bool
    finding_id: int
    archived_paths: list[str] = []
    skipped: list[str] = []
    error: str | None = None


class FinalizeReportRequest(BaseModel):
    paths: list[str]


class FinalizeReportResponse(BaseModel):
    success: bool
    archived_paths: list[str] = []
    skipped: list[str] = []
    error: str | None = None


class ArchiveStatusResponse(BaseModel):
    configured: bool
    archive_root: str | None
    reports_dir: str | None
    evidence_dir: str | None


@router.get("/engagements/{engagement_id}/archive-status",
            response_model=ArchiveStatusResponse)
def archive_status(engagement_id: int, request: Request) -> ArchiveStatusResponse:
    factory = request.app.state.engine_state.session_factory
    settings = request.app.state.settings
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        client_name = e.client
    archive = archive_paths_for(client_name, settings)
    if archive is None:
        return ArchiveStatusResponse(configured=False, archive_root=None,
                                     reports_dir=None, evidence_dir=None)
    return ArchiveStatusResponse(
        configured=True,
        archive_root=str(settings.archive_root),
        reports_dir=str(archive.reports),
        evidence_dir=str(archive.evidence),
    )


@router.post("/engagements/{engagement_id}/findings/{finding_id}/finalize",
             response_model=FinalizeFindingResponse)
def finalize_finding(engagement_id: int, finding_id: int,
                     request: Request) -> FinalizeFindingResponse:
    factory = request.app.state.engine_state.session_factory
    settings = request.app.state.settings
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        engagement = s.get(m.Engagement, engagement_id)
        rows = s.execute(
            select(m.Evidence).where(m.Evidence.finding_id == finding_id)
        ).scalars().all()
        evidence_dicts = [
            {"id": e.id, "path": e.path, "redacted_path": e.redacted_path}
            for e in rows
        ]
        client_name = engagement.client

    result = finalize_evidence_for_finding(
        client=client_name, finding_id=finding_id,
        evidence_rows=evidence_dicts, settings=settings,
    )

    if result.success:
        # Stamp finalized_at on every evidence row + flip finding status.
        with session_scope(factory) as s:
            now = now_utc()
            for ev in s.execute(
                select(m.Evidence).where(m.Evidence.finding_id == finding_id)
            ).scalars().all():
                ev.finalized_at = now
            f = s.get(m.Finding, finding_id)
            if f is not None:
                f.finalized_at = now
                f.status = m.FindingStatus.REPORTED

    return FinalizeFindingResponse(
        success=result.success, finding_id=finding_id,
        archived_paths=result.archived_paths, skipped=result.skipped,
        error=result.error,
    )


@router.post("/engagements/{engagement_id}/finalize-report",
             response_model=FinalizeReportResponse)
def finalize_report_endpoint(engagement_id: int, payload: FinalizeReportRequest,
                              request: Request) -> FinalizeReportResponse:
    factory = request.app.state.engine_state.session_factory
    settings = request.app.state.settings
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        client_name = e.client

    result = finalize_report(
        client=client_name,
        src_paths=[Path(p) for p in payload.paths],
        settings=settings,
    )
    return FinalizeReportResponse(
        success=result.success, archived_paths=result.archived_paths,
        skipped=result.skipped, error=result.error,
    )
