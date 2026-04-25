"""Engagement CRUD."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from ...core import models as m
from ...core.db import session_scope
from ...core.paths import to_canonical
from ...core.storage import EngagementPaths
from ..auth import require_token_dep
from ..schemas import EngagementCreate, EngagementOut

router = APIRouter(prefix="/engagements", tags=["engagements"], dependencies=[require_token_dep])


def _serialise(e: m.Engagement) -> EngagementOut:
    return EngagementOut.model_validate(e)


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
def create(payload: EngagementCreate, request: Request) -> EngagementOut:
    factory = request.app.state.engine_state.session_factory
    paths = EngagementPaths.for_engagement(payload.client).ensure()
    with session_scope(factory) as s:
        existing = s.scalar(select(m.Engagement).where(m.Engagement.client == payload.client))
        if existing is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "client already exists")
        eng = m.Engagement(
            client=payload.client,
            primary_domain=payload.primary_domain,
            notes=payload.notes,
            root_dir=to_canonical(paths.root),
            status=m.EngagementStatus.PLANNING,
        )
        for rule in payload.scope:
            kind = rule.get("kind", "exact").lower()
            pattern = rule.get("pattern", "").strip()
            if not pattern:
                continue
            try:
                kind_enum = m.ScopeKind(kind)
            except ValueError as exc:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    f"invalid scope kind: {kind}") from exc
            eng.scope_rules.append(m.ScopeRule(kind=kind_enum, pattern=pattern))
        s.add(eng)
        s.flush()
        return _serialise(eng)


@router.get("", response_model=list[EngagementOut])
def list_engagements(request: Request) -> list[EngagementOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        rows = s.execute(select(m.Engagement).order_by(m.Engagement.created_at)).scalars().all()
        return [_serialise(e) for e in rows]


@router.get("/{engagement_id}", response_model=EngagementOut)
def get(engagement_id: int, request: Request) -> EngagementOut:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        return _serialise(e)


@router.get("/{engagement_id}/scope")
def get_scope(engagement_id: int, request: Request) -> list[dict]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        return [{"kind": r.kind.value, "pattern": r.pattern, "note": r.note}
                for r in e.scope_rules]
