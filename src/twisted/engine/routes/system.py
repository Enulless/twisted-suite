"""System endpoints: health, version, procedure metadata."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from ... import __version__
from ..auth import require_token_dep
from ..schemas import ProcedureSummary

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@router.get("/procedures", dependencies=[require_token_dep])
def list_procedures(request: Request) -> list[ProcedureSummary]:
    procs = request.app.state.engine_state.procedures.all()
    out: list[ProcedureSummary] = []
    for p in procs.values():
        out.append(
            ProcedureSummary(
                id=p.id, name=p.name, description=p.description,
                stages=[
                    {
                        "id": st.id, "name": st.name, "objective": st.objective,
                        "steps": [
                            {"id": sp.id, "name": sp.name, "mode": sp.mode,
                             "runtime": sp.runtime, "requires": sp.requires}
                            for sp in st.steps
                        ],
                    }
                    for st in p.stages
                ],
            )
        )
    return out


@router.get("/procedures/{procedure_id}/steps/{step_id:path}",
            dependencies=[require_token_dep])
def get_step(request: Request, procedure_id: str, step_id: str) -> dict:
    procs = request.app.state.engine_state.procedures
    try:
        proc = procs.get(procedure_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "procedure not found") from e
    try:
        step = proc.step(step_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "step not found") from e
    return {
        "id": step.id, "name": step.name, "stage": step.stage,
        "mode": step.mode, "runtime": step.runtime, "requires": step.requires,
        "why": step.why, "what_to_collect": step.what_to_collect,
        "module": step.module, "params": step.params,
        "prompts": step.prompts,
        "collect": [c.__dict__ for c in step.collect],
        "training": step.training, "next": step.next,
    }
