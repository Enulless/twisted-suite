"""Practice-lab API: list, status, up/down, logs.

These are blocking calls that shell out to ``docker compose``; for
single-user localhost operation that's fine. Long-running bring-up
(image pulls etc.) can take minutes, so the timeouts are generous.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from ...labs import (
    LAB_CATALOGUE,
    LabError,
    docker_available,
    get_lab,
    lab_status,
    take_lab_down,
)
from ...labs import (
    lab_logs as run_logs,
)
from ...labs import (
    lab_up as run_up,
)
from ..auth import require_token_dep

router = APIRouter(prefix="/labs", tags=["labs"],
                   dependencies=[require_token_dep])


class LabSummary(BaseModel):
    id: str
    name: str
    description: str
    state: str
    target_url: str
    project_name: str
    services: dict[str, str] = {}
    practice_for: list[str] = []


class LabActionRequest(BaseModel):
    port: int | None = None
    wait_seconds: int = 0


class LabActionResponse(BaseModel):
    success: bool
    available: bool
    state: str | None = None
    output: str = ""
    error: str | None = None


class LabLogsResponse(BaseModel):
    success: bool
    available: bool
    output: str
    error: str | None = None


def _resolve(lab_id: str):
    try:
        return get_lab(lab_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lab not found") from e


def _summarise(spec) -> LabSummary:
    st = lab_status(spec)
    return LabSummary(
        id=spec.id, name=spec.name, description=spec.description,
        state=st.state.value, target_url=spec.target_url,
        project_name=spec.project_name,
        services=st.services,
        practice_for=list(spec.practice_for),
    )


@router.get("", response_model=list[LabSummary])
def list_labs() -> list[LabSummary]:
    return [_summarise(spec) for spec in LAB_CATALOGUE.values()]


@router.get("/_meta")
def lab_meta() -> dict:
    """Capability probe: does the engine host have docker installed?"""
    return {"docker_available": docker_available()}


@router.get("/{lab_id}", response_model=LabSummary)
def get_one_lab(lab_id: str) -> LabSummary:
    return _summarise(_resolve(lab_id))


@router.post("/{lab_id}/up", response_model=LabActionResponse)
def up_lab(lab_id: str,
           payload: LabActionRequest | None = None) -> LabActionResponse:
    spec = _resolve(lab_id)
    payload = payload or LabActionRequest()
    try:
        result = run_up(spec, port=payload.port,
                        wait_seconds=payload.wait_seconds)
    except LabError as e:
        return LabActionResponse(success=False, available=False, error=str(e))
    return LabActionResponse(
        success=result.success, available=result.available,
        state=result.state.value if result.state else None,
        output=result.output, error=result.error,
    )


@router.post("/{lab_id}/down", response_model=LabActionResponse)
def down_lab(lab_id: str,
             keep_volumes: bool = Query(False, description="Skip -v")
             ) -> LabActionResponse:
    spec = _resolve(lab_id)
    result = take_lab_down(spec, volumes=not keep_volumes)
    return LabActionResponse(
        success=result.success, available=result.available,
        state=result.state.value if result.state else None,
        output=result.output, error=result.error,
    )


@router.get("/{lab_id}/logs", response_model=LabLogsResponse)
def logs_for_lab(lab_id: str, tail: int = 100) -> LabLogsResponse:
    spec = _resolve(lab_id)
    result = run_logs(spec, tail=tail)
    return LabLogsResponse(
        success=result.success, available=result.available,
        output=result.output, error=result.error,
    )
