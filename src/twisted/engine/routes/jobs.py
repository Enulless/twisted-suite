"""Step-run + job lifecycle endpoints.

Flow:
  1. Operator (CLI/dashboard) POSTs /steps/run -> creates StepRun + Job (pending).
  2. Worker long-polls /jobs/next?caps=... -> claims a matching pending job.
  3. Worker executes module locally, POSTs /jobs/{id}/result back.
  4. Engine persists artifacts/assets/findings/evidence and marks job done.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from ...core import models as m
from ...core import tool_policy as tp
from ...core.db import session_scope
from ...core.evidence import sha256_file
from ...core.paths import to_canonical
from ...core.storage import EngagementPaths
from ..auth import require_token_dep
from ..schemas import (
    AssetUpsert,
    EvidenceIn,
    FindingDraftIn,
    JobOffer,
    JobOut,
    JobResult,
    StepRunOut,
    StepRunRequest,
)
from .assets import upsert_assets_in_session
from .findings import _to_severity

router = APIRouter(tags=["jobs"], dependencies=[require_token_dep])


def _serialise_run(sr: m.StepRun) -> StepRunOut:
    return StepRunOut.model_validate(sr)


def _serialise_job(j: m.Job) -> JobOut:
    return JobOut.model_validate(j)


# ──────────────────────────── Submit a step ────────────────────────────


@router.post("/steps/run", response_model=StepRunOut, status_code=status.HTTP_201_CREATED)
def queue_step(payload: StepRunRequest, request: Request) -> StepRunOut:
    procs = request.app.state.engine_state.procedures
    factory = request.app.state.engine_state.session_factory
    try:
        step = procs.step(payload.step_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"step '{payload.step_id}' not found") from e

    with session_scope(factory) as s:
        e = s.get(m.Engagement, payload.engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")

        # RoE tool-policy gate: refuse to queue a step that's been
        # blocked for this engagement (either directly or via a
        # cascaded capability block).
        decision = tp.is_step_allowed(s, e.id, step)
        if not decision.allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "blocked_by_tool_policy",
                    "reason": decision.reason,
                    "target_kind": decision.target_kind,
                    "target_value": decision.target_value,
                },
            )

        # Merge engagement context into params (so {{ engagement.primary_domain }}
        # placeholders resolve worker-side).
        merged_params = {**(step.params or {}), **(payload.params or {})}
        # Render simple placeholders inline: `{{engagement.primary_domain}}`
        merged_params = {
            k: (e.primary_domain if isinstance(v, str)
                                  and "engagement.primary_domain" in v else v)
            for k, v in merged_params.items()
        }
        sr = m.StepRun(
            engagement_id=e.id, procedure=step.procedure, stage=step.stage,
            step_id=step.id, mode=m.StepMode(step.mode),
            status=m.StepStatus.PENDING, params=merged_params,
        )
        sr.job = m.Job(
            runtime=m.JobRuntime(step.runtime),
            requires=list(step.requires or []),
            state=m.JobState.PENDING,
        )
        s.add(sr)
        s.flush()
        return _serialise_run(sr)


# ──────────────────────────── Worker long-poll ────────────────────────────


def _matches(job: m.Job, runtime: str, capabilities: set[str]) -> bool:
    if job.runtime not in (m.JobRuntime.EITHER, m.JobRuntime(runtime)):
        return False
    needs = set(job.requires or [])
    return needs.issubset(capabilities)


@router.get("/jobs/next", response_model=JobOffer | None)
def claim_next_job(
    request: Request,
    worker_id: str,
    runtime: str = Query("linux"),
    capabilities: list[str] = Query(default=[]),
) -> JobOffer | None:
    """Atomically claim the oldest pending job that matches this worker."""
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    if runtime not in {"linux", "windows", "either"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid runtime")
    caps = set(capabilities or [])

    with session_scope(factory) as s:
        worker = s.get(m.Worker, worker_id)
        if worker is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "worker not registered")
        worker.last_seen = datetime.now(UTC)

        candidates = s.execute(
            select(m.Job).where(m.Job.state == m.JobState.PENDING).order_by(m.Job.created_at)
        ).scalars().all()
        for job in candidates:
            if not _matches(job, runtime, caps):
                continue
            # Resolve module + work_dir
            sr = job.step_run
            try:
                step = procs.step(sr.step_id)
            except KeyError:
                # Step removed — mark failed
                job.state = m.JobState.FAILED
                job.error = "step removed from procedure"
                continue
            engagement = sr.engagement
            # Defensive RoE check: tool policy may have flipped
            # to block this step or one of its capabilities AFTER
            # the job was queued. Skip such jobs (they remain pending
            # until either the policy is unblocked or an operator
            # cancels them).
            decision = tp.is_step_allowed(s, engagement.id, step)
            if not decision.allowed:
                continue
            paths = EngagementPaths.for_engagement(engagement.client).ensure()
            work_dir = paths.step_dir(sr.stage)
            # Atomic claim
            now = datetime.now(UTC)
            job.state = m.JobState.CLAIMED
            job.claimed_by = worker_id
            job.claimed_at = now
            sr.worker_id = worker_id
            sr.status = m.StepStatus.RUNNING
            sr.started_at = sr.started_at or now
            return JobOffer(
                job_id=job.id,
                step_run_id=sr.id,
                engagement_id=engagement.id,
                procedure=sr.procedure,
                stage=sr.stage,
                step_id=sr.step_id,
                module=step.module,
                params=sr.params or {},
                work_dir=to_canonical(work_dir),
            )
        return None


@router.post("/jobs/{job_id}/start")
def mark_running(job_id: int, request: Request) -> dict:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        job = s.get(m.Job, job_id)
        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
        job.state = m.JobState.RUNNING
        job.started_at = datetime.now(UTC)
        return {"id": job.id, "state": job.state.value}


@router.post("/jobs/{job_id}/result")
def submit_result(job_id: int, payload: JobResult, request: Request) -> dict:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        job = s.get(m.Job, job_id)
        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
        sr = job.step_run
        engagement = sr.engagement
        now = datetime.now(UTC)

        # Persist step run completion
        sr.status = m.StepStatus.DONE if payload.success else m.StepStatus.FAILED
        sr.ended_at = now
        sr.output_summary = payload.summary
        sr.error = payload.error
        sr.artifact_paths = list(payload.artifact_paths or [])

        # Job state
        job.state = m.JobState.DONE if payload.success else m.JobState.FAILED
        job.ended_at = now
        job.error = payload.error
        job.result = payload.extra or None

        # Upsert assets using the shared helper (handles dedup + scope check).
        upsert_assets_in_session(s, engagement, list(payload.assets), now=now)

        # Findings
        finding_ids: list[int] = []
        for fitem in payload.findings:
            asset_id = None
            if fitem.asset_host:
                asset = s.execute(
                    select(m.Asset).where(
                        m.Asset.engagement_id == engagement.id,
                        m.Asset.host == fitem.asset_host.lower().strip(),
                    )
                ).scalar_one_or_none()
                if asset is not None:
                    asset_id = asset.id
            f = m.Finding(
                engagement_id=engagement.id, asset_id=asset_id,
                title=fitem.title,
                severity=_to_severity(fitem.severity, fitem.cvss_score),
                cvss_score=fitem.cvss_score, cvss_vector=fitem.cvss_vector,
                cwe=fitem.cwe, affected_component=fitem.affected_component,
                description=fitem.description, repro_steps=fitem.repro_steps,
                remediation=fitem.remediation, references=fitem.references or [],
                status=m.FindingStatus.DRAFT,
            )
            s.add(f)
            s.flush()
            finding_ids.append(f.id)

        # Evidence (free-floating, attached to the engagement; the operator
        # links it to a finding from the dashboard).
        for ev in payload.evidence:
            from pathlib import Path as _Path
            canonical = to_canonical(ev.path)
            sha = ev.sha256
            size = ev.size_bytes
            p = _Path(canonical)
            if p.exists():
                if sha is None:
                    sha = sha256_file(p)
                if size is None:
                    size = p.stat().st_size
            try:
                kind_enum = m.EvidenceKind(ev.kind)
            except ValueError:
                kind_enum = m.EvidenceKind.FILE
            s.add(m.Evidence(
                engagement_id=engagement.id, kind=kind_enum,
                path=canonical, sha256=sha, size_bytes=size,
                host=ev.host, note=ev.note, captured_at=now,
                captured_by_worker=job.claimed_by,
            ))

        return {
            "step_run_id": sr.id,
            "status": sr.status.value,
            "asset_count": len(payload.assets),
            "finding_ids": finding_ids,
            "evidence_count": len(payload.evidence),
        }


# ──────────────────────────── Status views ────────────────────────────


@router.get("/engagements/{engagement_id}/runs", response_model=list[StepRunOut])
def list_runs(engagement_id: int, request: Request) -> list[StepRunOut]:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        rows = s.execute(
            select(m.StepRun)
            .where(m.StepRun.engagement_id == engagement_id)
            .order_by(m.StepRun.id)
        ).scalars().all()
        return [_serialise_run(r) for r in rows]


@router.get("/runs/{step_run_id}", response_model=StepRunOut)
def get_run(step_run_id: int, request: Request) -> StepRunOut:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        sr = s.get(m.StepRun, step_run_id)
        if sr is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "step run not found")
        return _serialise_run(sr)


# Silence linter for re-exports used implicitly.
_ = (AssetUpsert, FindingDraftIn, EvidenceIn)
