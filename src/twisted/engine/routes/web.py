"""HTML dashboard router.

Renders the Jinja2 templates in ``twisted.web.templates`` against the
same SQLite store the JSON API talks to. Data shaping is done here so
the templates can stay declarative.

Auth: every dashboard route depends on ``require_dashboard_session``,
which accepts either the ``Authorization: Bearer`` header (so curl /
tests still work) or the cookie set by ``POST /login``. See
``engine.web_auth`` for the rationale.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import markdown as _markdown
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ... import __version__
from ...core import models as m
from ...core.cvss import parse_vector, severity_for_score
from ...core.db import session_scope
from ...modules.recon.risk_scoring import tier as risk_tier
from ...training import LessonNotFound, QuizNotFound, grade
from ..auth import read_token
from ..web_auth import (
    is_valid as session_is_valid,
)
from ..web_auth import (
    make_logout_response,
    make_session_cookie_response,
    require_dashboard_session,
)
from . import training as training_routes

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
    base = {
        "request": request,
        "version": __version__,
        "engine_url": str(request.base_url).rstrip("/"),
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


@router.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
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
    return _t().TemplateResponse(
        request, "training_detail.html",
        _ctx(request, lesson=lesson_view, lesson_html=lesson_html,
             quiz=quiz_public, progress=progress, user=user),
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
