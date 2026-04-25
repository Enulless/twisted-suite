"""Worker registration + heartbeat."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from ...core import models as m
from ...core.db import session_scope
from ..auth import require_token_dep
from ..schemas import WorkerOut, WorkerRegister

router = APIRouter(prefix="/workers", tags=["workers"], dependencies=[require_token_dep])


def _serialise(w: m.Worker) -> WorkerOut:
    return WorkerOut.model_validate(w)


@router.post("/register", response_model=WorkerOut, status_code=status.HTTP_201_CREATED)
def register(payload: WorkerRegister, request: Request) -> WorkerOut:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        existing = s.get(m.Worker, payload.id)
        now = datetime.now(UTC)
        if existing is None:
            w = m.Worker(
                id=payload.id, hostname=payload.hostname, os=payload.os,
                capabilities=list(payload.capabilities),
                tags=list(payload.tags) if payload.tags else None,
                version=payload.version,
                status=m.WorkerStatus.ONLINE,
                registered_at=now, last_seen=now,
            )
            s.add(w)
        else:
            existing.hostname = payload.hostname
            existing.os = payload.os
            existing.capabilities = list(payload.capabilities)
            existing.tags = list(payload.tags) if payload.tags else None
            existing.version = payload.version
            existing.status = m.WorkerStatus.ONLINE
            existing.last_seen = now
            w = existing
        s.flush()
        return _serialise(w)


@router.get("", response_model=list[WorkerOut])
def list_workers(request: Request) -> list[WorkerOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        workers = s.execute(select(m.Worker).order_by(m.Worker.registered_at)).scalars().all()
        return [_serialise(w) for w in workers]


@router.post("/{worker_id}/heartbeat", response_model=WorkerOut)
def heartbeat(worker_id: str, request: Request) -> WorkerOut:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        w = s.get(m.Worker, worker_id)
        if w is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "worker not registered")
        w.last_seen = datetime.now(UTC)
        if w.status == m.WorkerStatus.OFFLINE:
            w.status = m.WorkerStatus.ONLINE
        return _serialise(w)


@router.delete("/{worker_id}", status_code=status.HTTP_204_NO_CONTENT)
def unregister(worker_id: str, request: Request) -> None:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        w = s.get(m.Worker, worker_id)
        if w is None:
            return None
        w.status = m.WorkerStatus.OFFLINE
        return None
