"""Legacy HTML dashboard router.

DEPRECATED as of Phase 8: the React SPA at frontend/dist/ is now the
default UI. This module remains so existing operators keep their
muscle memory (``http://localhost:8000/dashboard/...`` still works),
and so the SPA can re-use the cookie auth + redact + finalize HTMX
endpoints that live here.

Removal plan (a future minor release):
1. Extract ``/login`` GET+POST and ``/logout`` into ``routes/auth_pages.py``
2. Extract ``/dashboard/.../redact`` into ``routes/redact.py`` (still
   needed by the SPA's evidence redaction button until the in-SPA
   canvas redactor ships)
3. Delete the remaining dashboard page handlers + templates
4. Delete the dashboard test files (they now duplicate SPA coverage)

Renders the Jinja2 templates in ``twisted.web.templates`` against the
same SQLite store the JSON API talks to. Data shaping is done here so
the templates can stay declarative.

Auth: every dashboard route depends on ``require_dashboard_session``,
which accepts either the ``Authorization: Bearer`` header (so curl /
tests still work) or the cookie set by ``POST /login``. See
``engine.web_auth`` for the rationale.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import markdown as _markdown
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ... import __version__
from ...core import models as m
from ...core.cvss import parse_vector, severity_for_score
from ...core.db import session_scope
from ...core.evidence import sha256_file
from ...core.finalize import (
    finalize_evidence_for_finding,
)
from ...core.finalize import (
    now_utc as _utcnow,
)
from ...core.redact import Rectangle, redact_file
from ...core.storage import EngagementPaths
from ...labs import (
    LAB_CATALOGUE,
    docker_available,
    get_lab,
    take_lab_down,
)
from ...labs import lab_for_step as _lab_for_step
from ...labs import lab_logs as run_lab_logs
from ...labs import lab_status as get_lab_status
from ...labs import lab_up as run_lab_up
from ...modules.recon.risk_scoring import tier as risk_tier
from ...training import LessonNotFound, QuizNotFound, grade
from ..auth import read_token
from ..legacy_gate import current_mode as legacy_mode
from ..legacy_gate import spa_equivalent
from ..web_auth import (
    is_valid as session_is_valid,
)
from ..web_auth import (
    make_logout_response,
    make_session_cookie_response,
    require_dashboard_session,
)
from . import training as training_routes  # noqa: I001

# Configured once at module import via ``configure_templates`` from
# ``app.py`` so the same Jinja2 environment (with the package
# ``twisted/web/templates`` directory mounted) is shared across views.
_templates: Jinja2Templates | None = None


def configure_templates(templates: Jinja2Templates) -> None:
    global _templates
    _templates = templates


def _t() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("web router used before configure_templates()")
    return _templates


router = APIRouter(tags=["dashboard"])


# ──────────────────────────── Helpers ────────────────────────────


def _ctx(request: Request, **extra: Any) -> dict[str, Any]:
    """Build the base template context with version + engine_url globals."""
    mode = legacy_mode()
    spa_link = spa_equivalent(request.url.path) if mode == "banner" else "/"
    base = {
        "request": request,
        "version": __version__,
        "engine_url": str(request.base_url).rstrip("/"),
        # Phase 8 deprecation banner — _base.html renders it when
        # legacy_ui_mode == "banner". The link points at the SPA
        # equivalent of the current legacy URL.
        "legacy_ui_mode": mode,
        "spa_equivalent_url": spa_link,
    }
    base.update(extra)
    return base


def _serialise_engagement(e: m.Engagement) -> dict[str, Any]:
    return {
        "id": e.id,
        "client": e.client,
        "primary_domain": e.primary_domain,
        "status": e.status.value,
        "created_at": e.created_at.isoformat(),
    }


def _serialise_worker(w: m.Worker) -> dict[str, Any]:
    return {
        "id": w.id,
        "hostname": w.hostname,
        "os": w.os,
        "status": w.status.value,
        "capabilities": list(w.capabilities or []),
        "last_seen": w.last_seen.isoformat() if w.last_seen else None,
    }


def _serialise_finding(f: m.Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "cwe": f.cwe,
        "status": f.status.value,
        "description": f.description,
        "affected_component": f.affected_component,
        "remediation": f.remediation,
    }


def _serialise_run(r: m.StepRun) -> dict[str, Any]:
    return {
        "id": r.id,
        "step_id": r.step_id,
        "stage": r.stage,
        "mode": r.mode.value,
        "status": r.status.value,
        "worker_id": r.worker_id,
        "output_summary": r.output_summary,
    }


def _procedure_for_engagement(procs, engagement: m.Engagement) -> dict[str, Any] | None:
    """Pick a procedure to display on the engagement page.

    For now: pick the procedure whose ID appears most often as the
    ``procedure`` column on the engagement's step_runs, falling back to
    the first loaded procedure (typically ``bb``). Once an engagement
    explicitly stores its primary procedure we'll read it from there.
    """
    counts: dict[str, int] = {}
    for r in engagement.step_runs:
        counts[r.procedure] = counts.get(r.procedure, 0) + 1
    chosen_id: str | None = None
    if counts:
        chosen_id = max(counts.items(), key=lambda kv: kv[1])[0]
    all_procs = procs.all()
    if not all_procs:
        return None
    proc = all_procs.get(chosen_id) if chosen_id else None
    if proc is None:
        proc = next(iter(all_procs.values()))
    return _serialise_procedure(proc)


def _serialise_procedure(proc) -> dict[str, Any]:
    return {
        "id": proc.id,
        "name": proc.name,
        "description": proc.description,
        "stages": [
            {
                "id": st.id,
                "name": st.name,
                "objective": st.objective,
                "steps": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "mode": s.mode,
                        "runtime": s.runtime,
                        "requires": list(s.requires or []),
                    }
                    for s in st.steps
                ],
            }
            for st in proc.stages
        ],
    }


def _bucketise_findings(findings: list[dict]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for f in findings:
        sev = f["severity"] if f["severity"] in buckets else "info"
        buckets[sev].append(f)
    return buckets


# ──────────────────────────── Login / logout ────────────────────────────


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str | None = None,
               error: str | None = None) -> HTMLResponse:
    # Auto-fill the token field from the local file when the dashboard
    # is co-located with the engine (the common single-user case). The
    # file is chmod 600 so this doesn't widen the trust boundary —
    # anyone who can read the file can already authenticate manually.
    prefilled = read_token() or ""
    return _t().TemplateResponse(
        request, "login.html",
        _ctx(request, next=next, error=error, prefilled_token=prefilled),
    )


@router.post("/login")
def login_submit(request: Request, token: str = Form(...),
                 next: str = Form("/dashboard/")) -> Any:
    if not session_is_valid(token.strip()):
        return _t().TemplateResponse(
            request, "login.html",
            _ctx(request, next=next, error="Invalid token.",
                 prefilled_token=token),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    target = next or "/dashboard/"
    # Constrain redirect target to local paths to avoid open-redirect.
    if not target.startswith("/") or target.startswith("//"):
        target = "/dashboard/"
    return make_session_cookie_response(target, token.strip())


@router.get("/logout")
def logout() -> Any:
    return make_logout_response()


# ──────────────────────────── Dashboard pages ────────────────────────────
#
# All HTML pages live under /dashboard/* to avoid colliding with the
# JSON API which holds /workers, /procedures, /engagements/* etc.
# A root-level GET / redirects to /dashboard/ so users land in the UI
# when they open the engine URL in a browser.


def make_root_redirect_to_dashboard() -> RedirectResponse:
    """Helper used by ``app.py`` when the SPA isn't built yet —
    in that case the root URL redirects to the legacy /dashboard/."""
    return RedirectResponse(url="/dashboard/",
                            status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/dashboard/", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def index(request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        engagements = [_serialise_engagement(e) for e in
                       s.execute(select(m.Engagement)
                                 .order_by(m.Engagement.created_at.desc()))
                        .scalars().all()]
        workers = [_serialise_worker(w) for w in
                   s.execute(select(m.Worker).order_by(m.Worker.last_seen.desc()))
                    .scalars().all()]
    return _t().TemplateResponse(
        request, "index.html",
        _ctx(request, engagements=engagements, workers=workers),
    )


@router.get("/dashboard/workers", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def workers_page(request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        workers = [_serialise_worker(w) for w in
                   s.execute(select(m.Worker).order_by(m.Worker.last_seen.desc()))
                    .scalars().all()]
    return _t().TemplateResponse(
        request, "workers.html", _ctx(request, workers=workers),
    )


@router.get("/htmx/workers", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def workers_fragment(request: Request) -> HTMLResponse:
    """HTMX polling target on the workers page (every 5 s)."""
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        workers = [_serialise_worker(w) for w in
                   s.execute(select(m.Worker).order_by(m.Worker.last_seen.desc()))
                    .scalars().all()]
    # Render a short inline fragment that hx-swaps the polling element
    # itself, preserving the auto-refresh trigger on the new node.
    online = sum(1 for w in workers if w["status"] == "online")
    html = (
        f'<p class="muted" hx-get="/htmx/workers" hx-trigger="every 5s" '
        f'hx-swap="outerHTML">{online}/{len(workers)} online · '
        f'updated {datetime.now(UTC).strftime("%H:%M:%S")} UTC</p>'
    )
    return HTMLResponse(html)


@router.get("/dashboard/procedures", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def procedures_page(request: Request) -> HTMLResponse:
    procs = request.app.state.engine_state.procedures
    return _t().TemplateResponse(
        request, "procedures.html",
        _ctx(request, procedures=[_serialise_procedure(p)
                                   for p in procs.all().values()]),
    )


@router.get("/dashboard/engagements/{engagement_id}", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def engagement_page(engagement_id: int, request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    procs = request.app.state.engine_state.procedures
    with session_scope(factory) as s:
        e = s.execute(
            select(m.Engagement)
            .options(selectinload(m.Engagement.scope_rules),
                     selectinload(m.Engagement.step_runs))
            .where(m.Engagement.id == engagement_id)
        ).scalar_one_or_none()
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        scope = [{"kind": r.kind.value, "pattern": r.pattern} for r in e.scope_rules]
        proc = _procedure_for_engagement(procs, e)
        eng = _serialise_engagement(e)
    return _t().TemplateResponse(
        request, "engagement.html",
        _ctx(request, engagement=eng, scope=scope,
             procedure_id=(proc or {}).get("id"),
             stages=(proc or {}).get("stages") or []),
    )


@router.get("/dashboard/engagements/{engagement_id}/assets",
            response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def assets_page(engagement_id: int, request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        rows = s.execute(
            select(m.Asset)
            .options(selectinload(m.Asset.ports), selectinload(m.Asset.techs),
                     selectinload(m.Asset.cves))
            .where(m.Asset.engagement_id == engagement_id)
            .order_by(m.Asset.host)
        ).scalars().all()
        assets = []
        for a in rows:
            assets.append({
                "id": a.id, "host": a.host, "ip": a.ip, "env_type": a.env_type,
                "in_scope": a.in_scope, "source": a.source,
                "risk_total": a.risk_total or 0,
                "tier": risk_tier(a.risk_total or 0) if (a.risk_total or 0) > 0 else "none",
                "ports": [{"port": p.port, "service": p.service} for p in a.ports],
                "techs": [{"name": t.name, "version": t.version} for t in a.techs],
                "cves":  [{"cve_id": c.cve_id} for c in a.cves],
            })
        eng = _serialise_engagement(e)
    return _t().TemplateResponse(
        request, "assets.html", _ctx(request, engagement=eng, assets=assets),
    )


@router.get("/dashboard/engagements/{engagement_id}/findings",
            response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def findings_page(engagement_id: int, request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        rows = s.execute(
            select(m.Finding)
            .where(m.Finding.engagement_id == engagement_id)
            .order_by(m.Finding.created_at.desc())
        ).scalars().all()
        findings = [_serialise_finding(f) for f in rows]
        eng = _serialise_engagement(e)
    return _t().TemplateResponse(
        request, "findings.html",
        _ctx(request, engagement=eng, findings=findings,
             buckets=_bucketise_findings(findings)),
    )


@router.get("/dashboard/engagements/{engagement_id}/findings/{finding_id}",
            response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def finding_detail_page(engagement_id: int, finding_id: int,
                        request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        e = s.get(m.Engagement, engagement_id)
        eng = _serialise_engagement(e)
        finding = _serialise_finding(f)
    return _t().TemplateResponse(
        request, "finding_detail.html",
        _ctx(request, engagement=eng, finding=finding),
    )


# ──────────────────────────── Practice labs ────────────────────────────


def _lab_view(spec) -> dict[str, Any]:
    st = get_lab_status(spec)
    return {
        "id": spec.id,
        "name": spec.name,
        "description": spec.description,
        "state": st.state.value,
        "target_url": spec.target_url,
        "project_name": spec.project_name,
        "services": st.services,
        "practice_for": list(spec.practice_for),
    }


@router.get("/dashboard/labs", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def labs_index(request: Request) -> HTMLResponse:
    labs = [_lab_view(spec) for spec in LAB_CATALOGUE.values()]
    return _t().TemplateResponse(
        request, "labs.html",
        _ctx(request, labs=labs, docker_available=docker_available()),
    )


@router.post("/dashboard/labs/{lab_id}/up", response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
def dashboard_lab_up(lab_id: str) -> HTMLResponse:
    try:
        spec = get_lab(lab_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lab not found") from e
    result = run_lab_up(spec, wait_seconds=0)
    if not result.available:
        return HTMLResponse(
            f'<span class="flash-error">Docker unavailable: {result.error}</span>'
        )
    if result.success:
        return HTMLResponse(
            f'<span class="status status-online">{lab_id} brought up</span> '
            f'(state={result.state.value if result.state else "unknown"}). '
            f'<a href="/dashboard/labs">refresh</a>'
        )
    return HTMLResponse(
        f'<span class="flash-error">{lab_id} up failed: {result.error}</span>'
    )


@router.post("/dashboard/labs/{lab_id}/down", response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
def dashboard_lab_down(lab_id: str) -> HTMLResponse:
    try:
        spec = get_lab(lab_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lab not found") from e
    result = take_lab_down(spec, volumes=True)
    if not result.available:
        return HTMLResponse(
            f'<span class="flash-error">Docker unavailable: {result.error}</span>'
        )
    if result.success:
        return HTMLResponse(
            f'<span class="status status-offline">{lab_id} torn down</span>. '
            f'<a href="/dashboard/labs">refresh</a>'
        )
    return HTMLResponse(
        f'<span class="flash-error">{lab_id} down failed: {result.error}</span>'
    )


@router.get("/dashboard/labs/{lab_id}/logs", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def dashboard_lab_logs(lab_id: str, request: Request,
                       tail: int = 100) -> HTMLResponse:
    try:
        spec = get_lab(lab_id)
    except KeyError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lab not found") from e
    result = run_lab_logs(spec, tail=tail)
    return _t().TemplateResponse(
        request, "lab_logs.html",
        _ctx(request, lab={"id": spec.id, "name": spec.name},
             tail=tail, result={"available": result.available,
                                "output": result.output,
                                "error": result.error}),
    )


# ──────────────────────────── Training pages ────────────────────────────


def _training_user(request: Request) -> str:
    """Resolve the training username. For now: query/cookie/default.

    A future patch can persist the user via a separate cookie, but the
    cookie session today only carries the bearer token.
    """
    return request.query_params.get("user") or "default"


@router.get("/dashboard/training", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def training_index(request: Request,
                   procedure: str | None = None) -> HTMLResponse:
    lesson_repo, quiz_repo = training_routes._repos(request)
    factory = request.app.state.engine_state.session_factory
    user = _training_user(request)
    lessons = lesson_repo.all()
    quizzes = quiz_repo.all()
    rows: list[dict] = []
    completed_count = 0
    by_proc: dict[str, list[dict]] = {}
    with session_scope(factory) as s:
        for step_id, lsn in sorted(lessons.items()):
            if procedure and lsn.procedure != procedure:
                continue
            attempt = training_routes._last_attempt(s, user=user, step_id=step_id)
            row = {
                "step_id": step_id,
                "procedure": lsn.procedure,
                "stage": lsn.stage,
                "title": lsn.title,
                "has_quiz": step_id in quizzes,
                "last_score": attempt.score if attempt else None,
                "completed": bool(attempt and (attempt.score or 0.0) >= 0.7),
            }
            rows.append(row)
            if row["completed"]:
                completed_count += 1
            by_proc.setdefault(lsn.procedure, []).append(row)
    return _t().TemplateResponse(
        request, "training_index.html",
        _ctx(request, lessons=rows, by_procedure=by_proc, user=user,
             quiz_count=sum(1 for r in rows if r["has_quiz"]),
             completed_count=completed_count),
    )


def _latest_engagement_id(factory) -> int | None:
    """Pick the most recently created engagement to default the practice
    button against. Returns None if there are no engagements."""
    with session_scope(factory) as s:
        eng = s.execute(
            select(m.Engagement).order_by(m.Engagement.created_at.desc())
        ).scalars().first()
        return eng.id if eng else None


@router.get("/dashboard/training/{step_id}", response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def training_detail(step_id: str, request: Request) -> HTMLResponse:
    lesson_repo, quiz_repo = training_routes._repos(request)
    user = _training_user(request)
    try:
        lsn = lesson_repo.get(step_id)
    except LessonNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lesson not found") from e
    quiz_obj = None
    quiz_public = None
    try:
        quiz_obj = quiz_repo.get(step_id)
        quiz_public = {
            "id": quiz_obj.id, "step_id": quiz_obj.step_id,
            "title": quiz_obj.title, "pass_threshold": quiz_obj.pass_threshold,
            "questions": [
                {"id": q.id, "type": q.type, "prompt": q.prompt,
                 "choices": q.choices}
                for q in quiz_obj.questions
            ],
        }
    except QuizNotFound:
        pass
    factory = request.app.state.engine_state.session_factory
    progress = None
    with session_scope(factory) as s:
        attempt = training_routes._last_attempt(s, user=user, step_id=step_id)
        if attempt is not None:
            progress = {
                "score": attempt.score or 0.0,
                "passed": (attempt.score or 0.0) >= 0.7,
                "completed_at": attempt.completed_at,
            }
    lesson_view = {
        "step_id": lsn.step_id, "procedure": lsn.procedure,
        "stage": lsn.stage, "title": lsn.title,
        "estimated_minutes": lsn.estimated_minutes,
    }
    lesson_html = _markdown.markdown(
        lsn.body, extensions=["fenced_code", "tables"]
    )
    # Resolve practice-on-the-lab info if any lab advertises this step.
    practice_lab = None
    practice_engagement_id = None
    spec = _lab_for_step(step_id)
    if spec is not None:
        st = get_lab_status(spec)
        practice_lab = {
            "id": spec.id, "name": spec.name, "state": st.state.value,
            "target_url": spec.target_url,
        }
        practice_engagement_id = _latest_engagement_id(
            request.app.state.engine_state.session_factory
        )
    return _t().TemplateResponse(
        request, "training_detail.html",
        _ctx(request, lesson=lesson_view, lesson_html=lesson_html,
             quiz=quiz_public, progress=progress, user=user,
             practice_lab=practice_lab,
             practice_engagement_id=practice_engagement_id),
    )


@router.post("/dashboard/training/{step_id}/quiz",
             response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
async def training_quiz_submit(step_id: str, request: Request) -> HTMLResponse:
    """HTMX target: accept form-encoded quiz responses, grade, persist,
    and return a fragment with the per-question breakdown."""
    _, quiz_repo = training_routes._repos(request)
    try:
        quiz = quiz_repo.get(step_id)
    except QuizNotFound:
        return HTMLResponse(
            '<p class="flash-error">No quiz available for this lesson.</p>',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    form = await request.form()
    responses = {q.id: str(form.get(q.id, "")) for q in quiz.questions}
    user = _training_user(request)
    graded = grade(quiz, responses)
    when = datetime.now(UTC)
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        existing = s.execute(
            select(m.TrainingProgress).where(
                m.TrainingProgress.user == user,
                m.TrainingProgress.lesson_id == step_id,
                m.TrainingProgress.quiz_id == quiz.id,
            )
        ).scalar_one_or_none()
        notes = (f"correct={graded.correct_count}/{graded.total} "
                 f"passed={graded.passed}")
        if existing is not None:
            existing.score = graded.score
            existing.completed_at = when
            existing.notes = notes
        else:
            s.add(m.TrainingProgress(
                user=user, lesson_id=step_id, quiz_id=quiz.id,
                score=graded.score, completed_at=when, notes=notes,
            ))
    sev_class = "done" if graded.passed else "failed"
    parts = [
        f'<h4>Score: <span class="status status-{sev_class}">'
        f'{graded.correct_count}/{graded.total} '
        f'({graded.score:.0%}) — {"PASS" if graded.passed else "FAIL"}'
        f'</span></h4>'
    ]
    parts.append('<ul style="margin-top:8px">')
    for pq in graded.per_question:
        marker = "✓" if pq.correct else "✗"
        css = "status-done" if pq.correct else "status-failed"
        explain = (f'<br><span class="muted">{pq.explain.strip()}</span>'
                   if pq.explain else "")
        parts.append(
            f'<li><span class="status {css}">{marker}</span> '
            f'{pq.question_id}: answered <code>{pq.response or ""}</code>, '
            f'expected <code>{pq.expected}</code>{explain}</li>'
        )
    parts.append("</ul>")
    return HTMLResponse("".join(parts))


@router.get("/dashboard/engagements/{engagement_id}/runs",
            response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def runs_page(engagement_id: int, request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        e = s.get(m.Engagement, engagement_id)
        if e is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
        rows = s.execute(
            select(m.StepRun)
            .where(m.StepRun.engagement_id == engagement_id)
            .order_by(m.StepRun.id.desc())
        ).scalars().all()
        runs = [_serialise_run(r) for r in rows]
        eng = _serialise_engagement(e)
    return _t().TemplateResponse(
        request, "runs.html", _ctx(request, engagement=eng, runs=runs),
    )


# ──────────────────────────── HTMX: CVSS calculator ────────────────────────────


# ──────────────────────────── Finalize / Practice fragments ────────────────────────────


@router.post("/dashboard/engagements/{engagement_id}/findings/{finding_id}/finalize",
             response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
def dashboard_finalize_finding(engagement_id: int, finding_id: int,
                               request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    settings = request.app.state.settings
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        eng = s.get(m.Engagement, engagement_id)
        client_name = eng.client
        rows = s.execute(
            select(m.Evidence).where(m.Evidence.finding_id == finding_id)
        ).scalars().all()
        ev_dicts = [{"id": e.id, "path": e.path,
                     "redacted_path": e.redacted_path} for e in rows]
    result = finalize_evidence_for_finding(
        client=client_name, finding_id=finding_id,
        evidence_rows=ev_dicts, settings=settings,
    )
    if not result.success:
        return HTMLResponse(
            f'<p class="flash-error">Finalize failed: {result.error}</p>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    with session_scope(factory) as s:
        now = _utcnow()
        for ev in s.execute(
            select(m.Evidence).where(m.Evidence.finding_id == finding_id)
        ).scalars().all():
            ev.finalized_at = now
        f = s.get(m.Finding, finding_id)
        if f is not None:
            f.finalized_at = now
            f.status = m.FindingStatus.REPORTED
    parts = [
        f'<p><span class="status status-done">Marked final</span> — '
        f'finding #{finding_id} status set to REPORTED.</p>'
    ]
    if result.archived_paths:
        parts.append("<ul>")
        for p in result.archived_paths:
            parts.append(f'<li>archived: <code>{p}</code></li>')
        parts.append("</ul>")
    if result.skipped:
        parts.append("<p class='muted'>Skipped (file missing on disk):</p><ul>")
        for p in result.skipped:
            parts.append(f'<li><code>{p}</code></li>')
        parts.append("</ul>")
    return HTMLResponse("".join(parts))


@router.post("/dashboard/training/{step_id}/practice",
             response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
async def dashboard_practice_step(step_id: str, request: Request) -> HTMLResponse:
    """Queue ``step_id`` against the lab that advertises it, for the
    engagement supplied via the form's hidden ``engagement_id`` field.

    Brings the lab up if it isn't running, then POSTs /steps/run with
    a host param pointing at the lab's target URL host.
    """
    spec = _lab_for_step(step_id)
    if spec is None:
        return HTMLResponse(
            '<p class="flash-error">No practice lab is configured for this step.</p>',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    form = await request.form()
    raw_eng = form.get("engagement_id") or ""
    try:
        engagement_id = int(raw_eng)
    except (TypeError, ValueError):
        return HTMLResponse(
            '<p class="flash-error">Pick an engagement first.</p>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Ensure lab is up; bring it up if not.
    status_now = get_lab_status(spec).state.value
    bring_up_msg = ""
    if status_now != "up":
        if not docker_available():
            return HTMLResponse(
                '<p class="flash-error">Docker is not available on the engine '
                'host; cannot bring the lab up.</p>',
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        result = run_lab_up(spec, wait_seconds=60)
        if not result.success:
            return HTMLResponse(
                f'<p class="flash-error">Lab failed to start: {result.error}</p>',
                status_code=status.HTTP_502_BAD_GATEWAY,
            )
        bring_up_msg = f"<p>Brought <strong>{spec.id}</strong> up.</p>"

    # Queue a step run against the lab's target host.
    procs = request.app.state.engine_state.procedures
    try:
        step = procs.step(step_id)
    except KeyError:
        return HTMLResponse(
            f'<p class="flash-error">Step {step_id} is not in any '
            'loaded procedure.</p>',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    factory = request.app.state.engine_state.session_factory
    target_host = spec.target_url.replace("http://", "").rstrip("/")
    with session_scope(factory) as s:
        eng = s.get(m.Engagement, engagement_id)
        if eng is None:
            return HTMLResponse(
                '<p class="flash-error">Engagement not found.</p>',
                status_code=status.HTTP_404_NOT_FOUND,
            )
        sr = m.StepRun(
            engagement_id=eng.id, procedure=step.procedure, stage=step.stage,
            step_id=step.id, mode=m.StepMode(step.mode),
            status=m.StepStatus.PENDING,
            params={"host": target_host, "url": spec.target_url,
                    "hosts": [target_host]},
        )
        sr.job = m.Job(runtime=m.JobRuntime(step.runtime),
                       requires=list(step.requires or []),
                       state=m.JobState.PENDING)
        s.add(sr)
        s.flush()
        run_id = sr.id

    parts = [bring_up_msg, (
        f'<p><span class="status status-online">Queued</span> '
        f'<code>{step_id}</code> against <code>{spec.target_url}</code> '
        f'as run <a href="/dashboard/engagements/{engagement_id}/runs">'
        f'#{run_id}</a>.</p>'
    )]
    return HTMLResponse("".join(parts))


# ──────────────────────────── PII redaction ────────────────────────────


@router.get("/dashboard/engagements/{engagement_id}/findings/{finding_id}/redact",
            response_class=HTMLResponse,
            dependencies=[Depends(require_dashboard_session)])
def redact_form(engagement_id: int, finding_id: int,
                request: Request) -> HTMLResponse:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        eng = s.get(m.Engagement, engagement_id)
        engagement = _serialise_engagement(eng)
        finding = _serialise_finding(f)
    return _t().TemplateResponse(
        request, "redact.html",
        _ctx(request, engagement=engagement, finding=finding, message=None),
    )


@router.post("/dashboard/engagements/{engagement_id}/findings/{finding_id}/redact",
             response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
async def redact_submit(engagement_id: int, finding_id: int,
                        request: Request,
                        image: UploadFile = File(...),
                        rectangles: str = Form("[]")) -> Any:
    factory = request.app.state.engine_state.session_factory
    settings = request.app.state.settings
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is None or f.engagement_id != engagement_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        eng = s.get(m.Engagement, engagement_id)
        client_name = eng.client

    try:
        rect_list = json.loads(rectangles or "[]")
        if not isinstance(rect_list, list):
            raise ValueError("rectangles must be a JSON array")
        rects = [Rectangle.from_dict(r) for r in rect_list]
    except (ValueError, TypeError) as e:
        return _t().TemplateResponse(
            request, "redact.html",
            _ctx(request,
                 engagement=_serialise_engagement(eng),
                 finding=_serialise_finding(f),
                 message=f"Invalid rectangles payload: {e}"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Save the original to evidence/raw/, then write a redacted sibling.
    paths = EngagementPaths.for_engagement(client_name, settings).ensure()
    payload = await image.read()
    if not payload:
        return _t().TemplateResponse(
            request, "redact.html",
            _ctx(request,
                 engagement=_serialise_engagement(eng),
                 finding=_serialise_finding(f),
                 message="Empty file."),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    src_name = (image.filename or "screenshot.png").rsplit("/", 1)[-1]
    src_path = paths.evidence_raw / f"finding{finding_id}_{ts}_{src_name}"
    src_path.write_bytes(payload)
    redacted_path = src_path.parent / f"redacted_{src_path.name}"
    if not redacted_path.suffix.lower().endswith(("png", ".jpg", ".jpeg")):
        redacted_path = redacted_path.with_suffix(".png")
    result = redact_file(src_path, redacted_path, rects)

    # Attach as a new evidence row.
    sha_orig = sha256_file(src_path)
    with session_scope(factory) as s:
        ev = m.Evidence(
            engagement_id=engagement_id, finding_id=finding_id,
            kind=m.EvidenceKind.SCREENSHOT,
            path=str(src_path), redacted_path=str(result.redacted_path),
            sha256=result.sha256, size_bytes=result.redacted_path.stat().st_size,
            host="wsl",
            note=(f"redacted via dashboard ({result.rectangles_applied} "
                  f"rectangles), original sha256={sha_orig[:12]}"),
        )
        s.add(ev)

    return RedirectResponse(
        url=f"/dashboard/engagements/{engagement_id}/findings/{finding_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/dashboard/engagements/{engagement_id}/findings/{finding_id}/cvss",
             response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_session)])
async def cvss_calculate(engagement_id: int, finding_id: int,
                         request: Request) -> HTMLResponse:
    """HTMX target: take CVSS base-metric form fields, render the
    computed score + vector as an HTML fragment."""
    form = await request.form()
    parts = []
    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        v = form.get(k)
        if v:
            parts.append(f"{k}:{v}")
    if len(parts) != 8:
        return HTMLResponse(
            '<p class="flash-error">Pick a value for every base metric.</p>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    vector = "CVSS:3.1/" + "/".join(parts)
    try:
        cvss = parse_vector(vector)
        score = cvss.base_score()
    except (KeyError, ValueError) as e:
        return HTMLResponse(
            f'<p class="flash-error">Invalid vector: {e}</p>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    sev = severity_for_score(score)
    sev_class = sev.lower()
    # Persist to the finding so a refresh shows the computed values.
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, finding_id)
        if f is not None and f.engagement_id == engagement_id:
            f.cvss_score = score
            f.cvss_vector = vector
    html = (
        f'<div>'
        f'<h4>Score: <span class="status status-{sev_class}">{score:.1f} ({sev})</span></h4>'
        f'<p class="muted"><code>{vector}</code></p>'
        f'<p class="muted">Saved to finding #{finding_id}. '
        f'<a href="/dashboard/engagements/{engagement_id}/findings/{finding_id}">'
        f'Refresh</a> to see it persisted.</p>'
        f'</div>'
    )
    return HTMLResponse(html)
