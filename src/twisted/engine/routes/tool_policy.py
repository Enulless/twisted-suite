"""RoE tool-policy endpoints.

  GET    /engagements/{id}/tool-policy            full snapshot
  GET    /engagements/{id}/tool-policy/inventory  list every step + cap
  PUT    /engagements/{id}/tool-policy/step/{step_id}        body {allowed, note}
  PUT    /engagements/{id}/tool-policy/capability/{cap}      body {allowed, note}
  POST   /engagements/{id}/tool-policy/preset/{name}         (open_bug_bounty/no_dos/read_only_recon)
  DELETE /engagements/{id}/tool-policy                       wipe all rows
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...core import models as m
from ...core import tool_policy as tp
from ...core.db import session_scope
from ..auth import require_token_dep

router = APIRouter(prefix="/engagements/{engagement_id}/tool-policy",
                   tags=["tool-policy"], dependencies=[require_token_dep])


# ──────────────────────────── Schemas ────────────────────────────


class PolicyRow(BaseModel):
    target_kind: str
    target_value: str
    allowed: bool
    note: str | None = None
    updated_at: str | None = None


class StepInventoryItem(BaseModel):
    step_id: str
    name: str
    procedure: str
    stage: str | None
    mode: str
    runtime: str
    requires: list[str] = Field(default_factory=list)
    allowed: bool
    block_reason: str | None = None
    block_kind: str | None = None  # "step" | "capability"


class CapabilityInventoryItem(BaseModel):
    capability: str
    allowed: bool
    step_count: int
    note: str | None = None


class ToolPolicySnapshot(BaseModel):
    engagement_id: int
    rows: list[PolicyRow]
    capabilities_blocked: list[str]
    steps_blocked: list[str]
    presets_available: list[str]


class ToolPolicyInventory(BaseModel):
    engagement_id: int
    capabilities: list[CapabilityInventoryItem]
    steps: list[StepInventoryItem]


class PolicyToggleRequest(BaseModel):
    allowed: bool
    note: str | None = None


class PresetApplyResponse(BaseModel):
    preset: str
    cleared: int
    capability_blocks: list[str]
    step_blocks: list[str]


# ──────────────────────────── Helpers ────────────────────────────


def _serialise_row(r: m.EngagementToolPolicy) -> PolicyRow:
    return PolicyRow(
        target_kind=r.target_kind.value,
        target_value=r.target_value,
        allowed=r.allowed,
        note=r.note,
        updated_at=r.updated_at.isoformat() if r.updated_at else None,
    )


def _ensure_engagement(session, engagement_id: int) -> m.Engagement:
    eng = session.get(m.Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return eng


# ──────────────────────────── Endpoints ────────────────────────────


@router.get("", response_model=ToolPolicySnapshot)
def get_policy(engagement_id: int, request: Request) -> ToolPolicySnapshot:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        rows = s.execute(
            select(m.EngagementToolPolicy)
            .where(m.EngagementToolPolicy.engagement_id == engagement_id)
            .order_by(m.EngagementToolPolicy.target_kind,
                      m.EngagementToolPolicy.target_value)
        ).scalars().all()
        steps_blocked = sorted(
            r.target_value for r in rows
            if r.target_kind == m.ToolPolicyKind.STEP and not r.allowed
        )
        caps_blocked = sorted(
            r.target_value for r in rows
            if r.target_kind == m.ToolPolicyKind.CAPABILITY and not r.allowed
        )
        return ToolPolicySnapshot(
            engagement_id=engagement_id,
            rows=[_serialise_row(r) for r in rows],
            capabilities_blocked=caps_blocked,
            steps_blocked=steps_blocked,
            presets_available=list(tp.PRESETS),
        )


@router.get("/inventory", response_model=ToolPolicyInventory)
def get_inventory(engagement_id: int, request: Request) -> ToolPolicyInventory:
    """Every step + every capability + their current allow/block state.

    This is what the dashboard's Tool Policy page renders. Steps that
    are blocked via a capability cascade are flagged with the relevant
    ``block_kind`` / ``block_reason`` so the UI can grey them out and
    show the cause.
    """
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        # Pre-load policy rows once
        blocked_steps, blocked_caps = tp._load_policy(s, engagement_id)

        cap_to_steps: dict[str, list[str]] = {}
        steps_inventory: list[StepInventoryItem] = []
        for proc in procs.all().values():
            for step in proc.all_steps():
                for cap in step.requires or []:
                    cap_to_steps.setdefault(cap, []).append(step.id)
                allowed = True
                block_kind = None
                block_reason = None
                if step.id in blocked_steps:
                    row = blocked_steps[step.id]
                    allowed = False
                    block_kind = "step"
                    block_reason = (row.note
                                    or "blocked directly by RoE")
                else:
                    for cap in step.requires or []:
                        if cap in blocked_caps:
                            row = blocked_caps[cap]
                            allowed = False
                            block_kind = "capability"
                            block_reason = (
                                row.note
                                or f"required capability {cap!r} blocked by RoE"
                            )
                            break
                steps_inventory.append(StepInventoryItem(
                    step_id=step.id, name=step.name,
                    procedure=proc.id, stage=step.stage,
                    mode=step.mode, runtime=step.runtime,
                    requires=list(step.requires or []),
                    allowed=allowed, block_reason=block_reason,
                    block_kind=block_kind,
                ))

        capabilities_inventory: list[CapabilityInventoryItem] = []
        for cap in tp.all_known_capabilities(procs):
            row = blocked_caps.get(cap)
            capabilities_inventory.append(CapabilityInventoryItem(
                capability=cap,
                allowed=row is None,
                step_count=len(cap_to_steps.get(cap, [])),
                note=row.note if row else None,
            ))
        return ToolPolicyInventory(
            engagement_id=engagement_id,
            capabilities=capabilities_inventory,
            steps=steps_inventory,
        )


@router.put("/step/{step_id:path}", response_model=PolicyRow)
def toggle_step(engagement_id: int, step_id: str,
                payload: PolicyToggleRequest, request: Request) -> PolicyRow:
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    # Validate the step actually exists in some loaded procedure.
    try:
        procs.step(step_id)
    except KeyError as e:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"step {step_id!r} not found in any loaded procedure",
        ) from e
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        row = tp.upsert_policy(
            s, engagement_id,
            target_kind=m.ToolPolicyKind.STEP.value,
            target_value=step_id,
            allowed=payload.allowed, note=payload.note,
        )
        s.flush()
        return _serialise_row(row)


@router.put("/capability/{capability}", response_model=PolicyRow)
def toggle_capability(engagement_id: int, capability: str,
                      payload: PolicyToggleRequest,
                      request: Request) -> PolicyRow:
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    known = set(tp.all_known_capabilities(procs))
    if capability not in known:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"capability {capability!r} is not used by any loaded procedure",
        )
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        row = tp.upsert_policy(
            s, engagement_id,
            target_kind=m.ToolPolicyKind.CAPABILITY.value,
            target_value=capability,
            allowed=payload.allowed, note=payload.note,
        )
        s.flush()
        return _serialise_row(row)


@router.post("/preset/{name}", response_model=PresetApplyResponse)
def apply_preset_endpoint(engagement_id: int, name: str,
                          request: Request) -> PresetApplyResponse:
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    if name not in tp.PRESETS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unknown preset {name!r}; available: {list(tp.PRESETS)}",
        )
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        result = tp.apply_preset(s, engagement_id, name, procs)
        return PresetApplyResponse(**result)


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def clear_policy(engagement_id: int, request: Request) -> None:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        _ensure_engagement(s, engagement_id)
        tp.clear_policy(s, engagement_id)
