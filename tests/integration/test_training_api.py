"""Integration tests for the engine training API.

Boots a real FastAPI app via TestClient, exercises GET /training,
GET /training/{step_id}, POST /training/{step_id}/quiz/submit, and
verifies the responses + that the score lands in the
``training_progress`` table.
"""

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
def api(tmp_path: Path,
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
    from tests.conftest import ApiClient
    client = ApiClient(TestClient(app))
    try:
        yield client, token
    finally:
        reset_settings(None)


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
def test_list_training_lessons(api) -> None:
    client, token = api
    r = client.get("/training", headers=_hdrs(token))
    assert r.status_code == 200
    rows = r.json()
    assert isinstance(rows, list)
    assert len(rows) > 0
    # All shipped lessons should appear
    step_ids = {r["step_id"] for r in rows}
    assert "bb.stage1.crtsh" in step_ids
    # Each row has the standard summary fields
    crtsh = next(r for r in rows if r["step_id"] == "bb.stage1.crtsh")
    assert crtsh["procedure"] == "bb"
    assert crtsh["stage"] == "stage1"
    assert crtsh["has_quiz"] is True
    assert crtsh["completed"] is False
    assert crtsh["last_score"] is None


@pytest.mark.integration
def test_list_training_filters_by_procedure(api) -> None:
    client, token = api
    r = client.get("/training", params={"procedure": "wifi"},
                   headers=_hdrs(token))
    assert r.status_code == 200
    rows = r.json()
    assert all(r["procedure"] == "wifi" for r in rows)
    assert any(r["step_id"].startswith("wifi.") for r in rows)


@pytest.mark.integration
def test_get_lesson_includes_body_sections_and_quiz(api) -> None:
    client, token = api
    r = client.get("/training/bb.stage1.crtsh", headers=_hdrs(token))
    assert r.status_code == 200
    payload = r.json()
    assert payload["step_id"] == "bb.stage1.crtsh"
    assert payload["procedure"] == "bb"
    assert payload["sections"]
    # The lesson body should include real content
    assert "Certificate Transparency" in payload["body"] or \
           "CT logs" in payload["body"]
    # A quiz exists for crtsh; it must NOT leak the answer key
    assert payload["quiz"] is not None
    assert payload["quiz"]["step_id"] == "bb.stage1.crtsh"
    for q in payload["quiz"]["questions"]:
        assert "answer" not in q
        assert q["id"] and q["prompt"] and q["type"]


@pytest.mark.integration
def test_get_lesson_404_on_unknown(api) -> None:
    client, token = api
    r = client.get("/training/bb.stage9.bogus", headers=_hdrs(token))
    assert r.status_code == 404


@pytest.mark.integration
def test_submit_quiz_grades_and_persists(api) -> None:
    client, token = api
    # First read the quiz so we know which question ids exist
    r = client.get("/training/bb.stage1.crtsh", headers=_hdrs(token))
    quiz = r.json()["quiz"]
    qids = [q["id"] for q in quiz["questions"]]
    # Use the locally-loaded quiz repo to know the correct answers (the
    # API correctly hides them); load from the package directly.
    from twisted.training import QuizRepo
    canonical = QuizRepo().get("bb.stage1.crtsh")
    correct = {q.id: q.answer for q in canonical.questions}

    r = client.post(
        "/training/bb.stage1.crtsh/quiz/submit",
        json={"user": "alice", "responses": correct},
        headers=_hdrs(token),
    )
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["correct_count"] == result["total"] == len(qids)
    assert result["score"] == 1.0
    assert result["passed"] is True
    assert result["user"] == "alice"
    assert len(result["per_question"]) == len(qids)
    for pq in result["per_question"]:
        assert pq["correct"] is True

    # Persisted row in training_progress
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
def test_submit_quiz_replaces_prior_attempt(api) -> None:
    client, token = api
    from twisted.training import QuizRepo
    canonical = QuizRepo().get("bb.stage1.crtsh")
    wrong = {q.id: "z" for q in canonical.questions}
    correct = {q.id: q.answer for q in canonical.questions}

    # First attempt: all wrong
    r1 = client.post(
        "/training/bb.stage1.crtsh/quiz/submit",
        json={"user": "bob", "responses": wrong},
        headers=_hdrs(token),
    )
    assert r1.json()["score"] == 0.0
    # Second attempt: all correct — replaces prior
    r2 = client.post(
        "/training/bb.stage1.crtsh/quiz/submit",
        json={"user": "bob", "responses": correct},
        headers=_hdrs(token),
    )
    assert r2.json()["score"] == 1.0

    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        rows = s.execute(
            select(m.TrainingProgress).where(
                m.TrainingProgress.user == "bob",
                m.TrainingProgress.lesson_id == "bb.stage1.crtsh",
            )
        ).scalars().all()
        # UNIQUE(user, lesson_id, quiz_id) means only one row exists
        assert len(rows) == 1
        assert rows[0].score == 1.0


@pytest.mark.integration
def test_submit_quiz_404_when_no_quiz(api) -> None:
    client, token = api
    r = client.post(
        "/training/bb.stage5.export_findings/quiz/submit",
        json={"user": "x", "responses": {}},
        headers=_hdrs(token),
    )
    # No quiz YAML for this step — graceful 404
    assert r.status_code == 404


@pytest.mark.integration
def test_completion_status_reflects_in_list(api) -> None:
    client, token = api
    from twisted.training import QuizRepo
    canonical = QuizRepo().get("bb.stage1.dns_enum")
    correct = {q.id: q.answer for q in canonical.questions}
    r = client.post(
        "/training/bb.stage1.dns_enum/quiz/submit",
        json={"user": "carol", "responses": correct},
        headers=_hdrs(token),
    )
    assert r.json()["passed"] is True

    r = client.get("/training", params={"user": "carol"},
                   headers=_hdrs(token))
    rows = r.json()
    dns = next(r for r in rows if r["step_id"] == "bb.stage1.dns_enum")
    assert dns["completed"] is True
    assert dns["last_score"] == 1.0


@pytest.mark.integration
def test_unauthenticated_training_request_rejected(api) -> None:
    client, _ = api
    r = client.get("/training")
    assert r.status_code == 401


@pytest.mark.integration
def test_get_progress_returns_last_attempt(api) -> None:
    client, token = api
    from twisted.training import QuizRepo
    canonical = QuizRepo().get("bb.stage1.crtsh")
    correct = {q.id: q.answer for q in canonical.questions}
    client.post(
        "/training/bb.stage1.crtsh/quiz/submit",
        json={"user": "dave", "responses": correct},
        headers=_hdrs(token),
    )
    r = client.get("/training/bb.stage1.crtsh/progress",
                   params={"user": "dave"}, headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body is not None
    assert body["score"] == 1.0
    assert body["passed"] is True
