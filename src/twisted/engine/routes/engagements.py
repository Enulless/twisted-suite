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


@router.get("/{engagement_id}/workflow-state")
def get_workflow_state(engagement_id: int, request: Request) -> dict:
    """Single-call snapshot for the SPA's persistent workflow stepper.

    Returns six steps (Setup/Tooling/Execute/Triage/Report/Finalize)
    each with a completion 0.0-1.0 and a short status badge string.
    """
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    settings = request.app.state.settings
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")

        # Setup: client (always set) + primary_domain + at least one
        # scope rule. 1.0 if all three present.
        setup_pieces = [bool(e.client),
                        bool(e.primary_domain),
                        bool(e.scope_rules)]
        setup_pct = sum(setup_pieces) / len(setup_pieces)

        # Tooling: derived from EngagementToolPolicy. 0 = no choices made
        # (default), 1 = at least one explicit allow OR block recorded.
        n_policy_rows = s.query(m.EngagementToolPolicy).filter(
            m.EngagementToolPolicy.engagement_id == engagement_id,
        ).count()
        n_caps_blocked = s.query(m.EngagementToolPolicy).filter(
            m.EngagementToolPolicy.engagement_id == engagement_id,
            m.EngagementToolPolicy.target_kind == m.ToolPolicyKind.CAPABILITY,
            m.EngagementToolPolicy.allowed == False,  # noqa: E712
        ).count()
        n_steps_blocked = s.query(m.EngagementToolPolicy).filter(
            m.EngagementToolPolicy.engagement_id == engagement_id,
            m.EngagementToolPolicy.target_kind == m.ToolPolicyKind.STEP,
            m.EngagementToolPolicy.allowed == False,  # noqa: E712
        ).count()
        tooling_pct = 1.0 if n_policy_rows > 0 else 0.0

        # Execute: step_runs done / total automatable steps in any
        # procedure. Approximate by counting unique completed step ids
        # against the union of all loaded step ids.
        all_steps = sum(len(proc.all_steps()) for proc in procs.all().values())
        runs = e.step_runs or []
        done = sum(1 for r in runs if r.status == m.StepStatus.DONE)
        running = sum(1 for r in runs if r.status == m.StepStatus.RUNNING)
        failed = sum(1 for r in runs if r.status == m.StepStatus.FAILED)
        pending = sum(1 for r in runs if r.status == m.StepStatus.PENDING)
        execute_pct = (done / all_steps) if all_steps else 0.0

        # Triage: fraction of findings that have moved beyond DRAFT.
        all_findings = e.findings or []
        triaged = sum(1 for f in all_findings
                      if f.status not in (m.FindingStatus.DRAFT,
                                          m.FindingStatus.NEEDS_VERIFICATION))
        triage_pct = (triaged / len(all_findings)) if all_findings else 0.0

        # Report: 1.0 if any finding has been finalised OR an explicit
        # reporting status has been set. Lightweight signal — operators
        # who haven't built a report yet show 0.0.
        finalised_findings = sum(1 for f in all_findings
                                 if f.finalized_at is not None)
        report_pct = 1.0 if finalised_findings > 0 else 0.0

        # Finalize: archive_root configured AND all findings finalised.
        archive_configured = bool(settings.archive_root)
        if all_findings:
            finalize_pct = (finalised_findings / len(all_findings)) \
                if archive_configured else 0.0
        else:
            finalize_pct = 0.0

        return {
            "engagement_id": engagement_id,
            "steps": [
                {
                    "id": "setup",
                    "label": "Setup",
                    "completion": setup_pct,
                    "summary": (
                        f"client + scope ({len(e.scope_rules)} rules)"
                        if e.scope_rules
                        else "client only — add a scope rule"
                    ),
                },
                {
                    "id": "tooling",
                    "label": "Tooling",
                    "completion": tooling_pct,
                    "summary": (
                        "default (everything allowed)"
                        if n_policy_rows == 0
                        else (
                            f"{n_caps_blocked} caps blocked, "
                            f"{n_steps_blocked} steps blocked"
                        )
                    ),
                },
                {
                    "id": "execute",
                    "label": "Execute",
                    "completion": execute_pct,
                    "summary": (
                        f"{done}/{all_steps} done"
                        + (f" · {running} running" if running else "")
                        + (f" · {failed} failed" if failed else "")
                        + (f" · {pending} pending" if pending else "")
                    ),
                },
                {
                    "id": "triage",
                    "label": "Triage",
                    "completion": triage_pct,
                    "summary": (
                        f"{triaged}/{len(all_findings)} triaged"
                        if all_findings else "no findings yet"
                    ),
                },
                {
                    "id": "report",
                    "label": "Report",
                    "completion": report_pct,
                    "summary": (
                        f"{finalised_findings} finding(s) finalised"
                        if finalised_findings else "no findings finalised yet"
                    ),
                },
                {
                    "id": "finalize",
                    "label": "Finalize",
                    "completion": finalize_pct,
                    "summary": (
                        "archive not configured — "
                        "set TWISTED_ARCHIVE_ROOT"
                        if not archive_configured
                        else f"{finalised_findings}/{len(all_findings)} archived"
                    ),
                },
            ],
            "stats": {
                "scope_rules": len(e.scope_rules),
                "asset_count": len(e.assets or []),
                "finding_count": len(all_findings),
                "step_runs_done": done,
                "step_runs_running": running,
                "step_runs_failed": failed,
                "policy_caps_blocked": n_caps_blocked,
                "policy_steps_blocked": n_steps_blocked,
                "archive_configured": archive_configured,
            },
        }
