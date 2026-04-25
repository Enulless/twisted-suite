"""Training-mode API: list lessons, fetch a lesson + its quiz, submit
quiz answers (graded server-side, persisted to ``training_progress``).

User identity is a free-form string (``user`` query/body param) per the
plan's "solo-use" model — no bcrypt, no session tables. The CLI and
dashboard default this to the OS username; tests can override.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...core import models as m
from ...core.db import session_scope
from ...training import (
    GradedQuiz,
    LessonNotFound,
    LessonRepo,
    QuizNotFound,
    QuizRepo,
    grade,
)
from ..auth import require_token_dep

router = APIRouter(prefix="/training", tags=["training"],
                   dependencies=[require_token_dep])


# ──────────────────────────── Schemas ────────────────────────────


class LessonSummary(BaseModel):
    step_id: str
    procedure: str
    stage: str | None
    title: str
    has_quiz: bool
    estimated_minutes: int | None
    completed: bool = False
    last_score: float | None = None


class LessonDetail(BaseModel):
    step_id: str
    procedure: str
    stage: str | None
    title: str
    body: str
    sections: dict[str, str]
    estimated_minutes: int | None
    quiz: QuizDetail | None = None
    progress: QuizAttempt | None = None


class QuizDetail(BaseModel):
    id: str
    step_id: str
    title: str
    pass_threshold: float
    questions: list[QuestionPublic]


class QuestionPublic(BaseModel):
    """Question shape sent to clients — never exposes the answer."""
    id: str
    type: str
    prompt: str
    choices: dict[str, str] = Field(default_factory=dict)


class QuizSubmit(BaseModel):
    user: str = "default"
    responses: dict[str, str]


class QuestionResultPublic(BaseModel):
    question_id: str
    correct: bool
    response: str | None
    expected: str
    explain: str | None = None


class QuizAttempt(BaseModel):
    quiz_id: str
    step_id: str
    user: str
    correct_count: int
    total: int
    score: float
    passed: bool
    completed_at: datetime
    per_question: list[QuestionResultPublic] = Field(default_factory=list)


# Resolve forward refs once classes exist
LessonDetail.model_rebuild()
QuizDetail.model_rebuild()


# ──────────────────────────── Helpers ────────────────────────────


def _repos(request: Request) -> tuple[LessonRepo, QuizRepo]:
    """Lazy-cache the lesson + quiz repos on the engine state."""
    state = request.app.state.engine_state
    if not hasattr(state, "lesson_repo") or state.lesson_repo is None:
        state.lesson_repo = LessonRepo()
    if not hasattr(state, "quiz_repo") or state.quiz_repo is None:
        state.quiz_repo = QuizRepo()
    return state.lesson_repo, state.quiz_repo


def _last_attempt(session, *, user: str, step_id: str) -> m.TrainingProgress | None:
    return session.execute(
        select(m.TrainingProgress)
        .where(m.TrainingProgress.user == user,
               m.TrainingProgress.lesson_id == step_id)
        .order_by(m.TrainingProgress.completed_at.desc())
    ).scalars().first()


def _quiz_to_public(quiz) -> QuizDetail:
    return QuizDetail(
        id=quiz.id, step_id=quiz.step_id, title=quiz.title,
        pass_threshold=quiz.pass_threshold,
        questions=[
            QuestionPublic(id=q.id, type=q.type, prompt=q.prompt, choices=q.choices)
            for q in quiz.questions
        ],
    )


def _graded_to_attempt(g: GradedQuiz, user: str, when: datetime) -> QuizAttempt:
    return QuizAttempt(
        quiz_id=g.quiz_id, step_id=g.step_id, user=user,
        correct_count=g.correct_count, total=g.total,
        score=g.score, passed=g.passed, completed_at=when,
        per_question=[
            QuestionResultPublic(
                question_id=q.question_id, correct=q.correct,
                response=q.response, expected=q.expected, explain=q.explain,
            )
            for q in g.per_question
        ],
    )


# ──────────────────────────── Routes ────────────────────────────


@router.get("", response_model=list[LessonSummary])
def list_lessons(request: Request, user: str = "default",
                 procedure: str | None = None) -> list[LessonSummary]:
    """List every available lesson with completion status for ``user``.

    Filter by ``procedure=bb|wp_stress|wifi`` to narrow the view.
    """
    lesson_repo, quiz_repo = _repos(request)
    factory = request.app.state.engine_state.session_factory
    lessons = lesson_repo.all()
    quizzes = quiz_repo.all()
    out: list[LessonSummary] = []
    with session_scope(factory) as s:
        for step_id, lsn in sorted(lessons.items()):
            if procedure and lsn.procedure != procedure:
                continue
            attempt = _last_attempt(s, user=user, step_id=step_id)
            out.append(LessonSummary(
                step_id=step_id, procedure=lsn.procedure, stage=lsn.stage,
                title=lsn.title, has_quiz=step_id in quizzes,
                estimated_minutes=lsn.estimated_minutes,
                completed=bool(attempt and (attempt.score or 0.0) >= 0.7),
                last_score=attempt.score if attempt else None,
            ))
    return out


@router.get("/{step_id}", response_model=LessonDetail)
def get_lesson(step_id: str, request: Request,
               user: str = "default") -> LessonDetail:
    lesson_repo, quiz_repo = _repos(request)
    try:
        lsn = lesson_repo.get(step_id)
    except LessonNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lesson not found") from e
    quiz_public: QuizDetail | None = None
    try:
        q = quiz_repo.get(step_id)
        quiz_public = _quiz_to_public(q)
    except QuizNotFound:
        pass
    factory = request.app.state.engine_state.session_factory
    progress: QuizAttempt | None = None
    with session_scope(factory) as s:
        attempt = _last_attempt(s, user=user, step_id=step_id)
        if attempt is not None:
            progress = QuizAttempt(
                quiz_id=attempt.quiz_id or "",
                step_id=step_id, user=user,
                correct_count=int((attempt.score or 0) * 100),
                total=100,
                score=attempt.score or 0.0,
                passed=(attempt.score or 0.0) >= 0.7,
                completed_at=attempt.completed_at,
            )
    return LessonDetail(
        step_id=lsn.step_id, procedure=lsn.procedure, stage=lsn.stage,
        title=lsn.title, body=lsn.body, sections=lsn.sections,
        estimated_minutes=lsn.estimated_minutes,
        quiz=quiz_public, progress=progress,
    )


@router.post("/{step_id}/quiz/submit", response_model=QuizAttempt)
def submit_quiz(step_id: str, payload: QuizSubmit,
                request: Request) -> QuizAttempt:
    _, quiz_repo = _repos(request)
    try:
        quiz = quiz_repo.get(step_id)
    except QuizNotFound as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "quiz not found for step") from e
    graded = grade(quiz, payload.responses)
    when = datetime.now(UTC)
    factory = request.app.state.engine_state.session_factory
    user = (payload.user or "default").strip() or "default"
    with session_scope(factory) as s:
        # Replace any prior attempt for the same user+lesson+quiz so the
        # UNIQUE(user, lesson_id, quiz_id) constraint stays satisfied.
        existing = s.execute(
            select(m.TrainingProgress).where(
                m.TrainingProgress.user == user,
                m.TrainingProgress.lesson_id == step_id,
                m.TrainingProgress.quiz_id == quiz.id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.score = graded.score
            existing.completed_at = when
            existing.notes = (
                f"correct={graded.correct_count}/{graded.total} "
                f"passed={graded.passed}"
            )
        else:
            s.add(m.TrainingProgress(
                user=user, lesson_id=step_id, quiz_id=quiz.id,
                score=graded.score, completed_at=when,
                notes=(f"correct={graded.correct_count}/{graded.total} "
                       f"passed={graded.passed}"),
            ))
    return _graded_to_attempt(graded, user=user, when=when)


@router.get("/{step_id}/progress", response_model=QuizAttempt | None)
def get_progress(step_id: str, request: Request,
                 user: str = "default") -> QuizAttempt | None:
    factory = request.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        attempt = _last_attempt(s, user=user, step_id=step_id)
        if attempt is None:
            return None
        return QuizAttempt(
            quiz_id=attempt.quiz_id or "",
            step_id=step_id, user=user,
            correct_count=0, total=0,  # raw breakdown isn't stored
            score=attempt.score or 0.0,
            passed=(attempt.score or 0.0) >= 0.7,
            completed_at=attempt.completed_at,
        )
