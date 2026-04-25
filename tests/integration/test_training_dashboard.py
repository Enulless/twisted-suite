"""Phase 6 dashboard tests — training index + lesson detail + quiz."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from twisted.core import models as m
from twisted.core.db import session_scope
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token


@pytest.fixture
def dash(tmp_path: Path,
         monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str]]:
    data = tmp_path / "data"
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(data))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{data}/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    token = ensure_token(s)
    client = TestClient(app, follow_redirects=False)
    try:
        yield client, token
    finally:
        reset_settings(None)


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
def test_training_index_renders(dash) -> None:
    client, token = dash
    r = client.get("/dashboard/training", headers=_hdrs(token))
    assert r.status_code == 200
    # Procedure section headers
    assert "bb (" in r.text
    assert "wp_stress (" in r.text
    assert "wifi (" in r.text
    # At least one row link
    assert "/dashboard/training/bb.stage1.crtsh" in r.text


@pytest.mark.integration
def test_training_index_filter_by_procedure(dash) -> None:
    client, token = dash
    r = client.get("/dashboard/training",
                   params={"procedure": "wifi"}, headers=_hdrs(token))
    assert r.status_code == 200
    assert "wifi" in r.text
    # bb shouldn't appear as a section header when filtered
    assert "bb (" not in r.text


@pytest.mark.integration
def test_training_detail_renders_markdown(dash) -> None:
    client, token = dash
    r = client.get("/dashboard/training/bb.stage1.crtsh", headers=_hdrs(token))
    assert r.status_code == 200
    # Markdown rendered to HTML
    assert "<h2>" in r.text or "<p>" in r.text
    assert "Certificate Transparency" in r.text or "CT log" in r.text
    # Quiz form is present
    assert ('hx-post="/dashboard/training/bb.stage1.crtsh/quiz"' in r.text)
    # No answer key leaked into the HTML
    # (Quiz YAML answers are only on the server)
    assert "answer:" not in r.text.lower() or "your answer" in r.text.lower()


@pytest.mark.integration
def test_training_detail_404_on_unknown(dash) -> None:
    client, token = dash
    r = client.get("/dashboard/training/bb.bogus.unknown", headers=_hdrs(token))
    assert r.status_code == 404


@pytest.mark.integration
def test_training_detail_no_quiz_message(dash) -> None:
    """A lesson that doesn't have a quiz YAML still renders, with an
    explanatory message instead of the form."""
    client, token = dash
    # Find a lesson that has no quiz
    from twisted.training import LessonRepo, QuizRepo
    lessons, quizzes = LessonRepo().all(), QuizRepo().all()
    no_quiz_step = next(sid for sid in lessons if sid not in quizzes)
    r = client.get(f"/dashboard/training/{no_quiz_step}", headers=_hdrs(token))
    assert r.status_code == 200
    assert "No quiz available" in r.text


@pytest.mark.integration
def test_training_quiz_submit_grades_and_persists(dash) -> None:
    client, token = dash
    from twisted.training import QuizRepo
    quiz = QuizRepo().get("bb.stage1.crtsh")
    form_data = {q.id: q.answer for q in quiz.questions}
    r = client.post(
        "/dashboard/training/bb.stage1.crtsh/quiz",
        data=form_data,
        params={"user": "alice"},
        headers=_hdrs(token),
    )
    assert r.status_code == 200
    assert "PASS" in r.text
    assert f"{len(quiz.questions)}/{len(quiz.questions)}" in r.text

    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        row = s.execute(
            select(m.TrainingProgress).where(
                m.TrainingProgress.user == "alice",
                m.TrainingProgress.lesson_id == "bb.stage1.crtsh",
            )
        ).scalar_one()
        assert row.score == 1.0


@pytest.mark.integration
def test_training_quiz_fail_renders_breakdown(dash) -> None:
    client, token = dash
    from twisted.training import QuizRepo
    quiz = QuizRepo().get("bb.stage1.crtsh")
    bad_data = {q.id: "z" for q in quiz.questions}
    r = client.post(
        "/dashboard/training/bb.stage1.crtsh/quiz",
        data=bad_data,
        headers=_hdrs(token),
    )
    assert r.status_code == 200
    assert "FAIL" in r.text
    # Per-question marks
    assert "✗" in r.text


@pytest.mark.integration
def test_training_completion_appears_in_index(dash) -> None:
    client, token = dash
    from twisted.training import QuizRepo
    quiz = QuizRepo().get("bb.stage1.crtsh")
    form_data = {q.id: q.answer for q in quiz.questions}
    client.post(
        "/dashboard/training/bb.stage1.crtsh/quiz",
        data=form_data,
        params={"user": "ed"},
        headers=_hdrs(token),
    )
    r = client.get("/dashboard/training", params={"user": "ed"},
                   headers=_hdrs(token))
    assert r.status_code == 200
    # The completed marker appears for crtsh (the row holds a ✓ class)
    assert "100%" in r.text


@pytest.mark.integration
def test_training_nav_link_in_base(dash) -> None:
    """Sanity: every dashboard page now has a nav link to /dashboard/training."""
    client, token = dash
    r = client.get("/dashboard/", headers=_hdrs(token))
    assert r.status_code == 200
    assert 'href="/dashboard/training"' in r.text
