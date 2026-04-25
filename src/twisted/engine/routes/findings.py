"""Finding + evidence routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from ...core import models as m
from ...core.cvss import severity_for_score
from ...core.db import session_scope
from ...core.evidence import sha256_file
from ...core.paths import to_canonical
from ..auth import require_token_dep
from ..schemas import EvidenceIn, FindingDraftIn, FindingOut

router = APIRouter(prefix="/engagements/{engagement_id}/findings", tags=["findings"],
                   dependencies=[require_token_dep])


_SEVERITY_MAP = {
    "info": m.FindingSeverity.INFO,
    "informational": m.FindingSeverity.INFO,
    "none": m.FindingSeverity.INFO,
    "low": m.FindingSeverity.LOW,
    "medium": m.FindingSeverity.MEDIUM,
    "high": m.FindingSeverity.HIGH,
    "critical": m.FindingSeverity.CRITICAL,
}


def _to_severity(text: str | None, score: float | None = None) -> m.FindingSeverity:
    if text:
        sev = _SEVERITY_MAP.get(text.lower())
        if sev is not None:
            return sev
    if score is not None:
        return _SEVERITY_MAP.get(severity_for_score(score).lower(), m.FindingSeverity.INFO)
    return m.FindingSeverity.INFO


def _serialise(f: m.Finding) -> FindingOut:
    return FindingOut.model_validate(f)


@router.get("", response_model=list[FindingOut])
def list_findings(engagement_id: int, request: Request,
                  severity: str | None = None) -> list[FindingOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        q = select(m.Finding).where(m.Finding.engagement_id == engagement_id)
        if severity:
            try:
                q = q.where(m.Finding.severity == _to_severity(severity))
            except ValueError as exc:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    f"invalid severity '{severity}'") from exc
        rows = s.execute(q.order_by(m.Finding.created_at)).scalars().all()
        return [_serialise(f) for f in rows]


@router.post("", response_model=list[FindingOut])
def create_findings(engagement_id: int, payload: list[FindingDraftIn],
                    request: Request) -> list[FindingOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        out: list[m.Finding] = []
        for item in payload:
            asset_id = None
            if item.asset_host:
                asset = s.execute(
                    select(m.Asset).where(
                        m.Asset.engagement_id == engagement_id,
                        m.Asset.host == item.asset_host.lower().strip(),
                    )
                ).scalar_one_or_none()
                if asset is not None:
                    asset_id = asset.id
            f = m.Finding(
                engagement_id=engagement_id, asset_id=asset_id,
                title=item.title,
                severity=_to_severity(item.severity, item.cvss_score),
                cvss_score=item.cvss_score, cvss_vector=item.cvss_vector,
                cwe=item.cwe, affected_component=item.affected_component,
                description=item.description, repro_steps=item.repro_steps,
                remediation=item.remediation, references=item.references or [],
                status=m.FindingStatus.DRAFT,
            )
            s.add(f)
            out.append(f)
        s.flush()
        return [_serialise(f) for f in out]


@router.post("/{finding_id}/evidence")
def attach_evidence(engagement_id: int, finding_id: int,
                    payload: list[EvidenceIn], request: Request) -> list[dict]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        added: list[m.Evidence] = []
        for item in payload:
            canonical = to_canonical(item.path)
            sha = item.sha256
            size = item.size_bytes
            p = Path(canonical)
            if p.exists() and (sha is None or size is None):
                if sha is None:
                    sha = sha256_file(p)
                if size is None:
                    size = p.stat().st_size
            ev = m.Evidence(
                engagement_id=engagement_id, finding_id=finding_id,
                kind=m.EvidenceKind(item.kind) if item.kind in m.EvidenceKind._value2member_map_
                                              else m.EvidenceKind.FILE,
                path=canonical, sha256=sha, size_bytes=size,
                host=item.host, note=item.note,
                captured_at=datetime.now(UTC),
            )
            s.add(ev)
            added.append(ev)
        s.flush()
        return [{"id": e.id, "path": e.path, "sha256": e.sha256, "kind": e.kind.value}
                for e in added]
