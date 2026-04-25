"""Integration tests for /api/engagements/{id}/workflow-state."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ApiClient
from twisted.core import models as m
from twisted.core.db import session_scope
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token


@pytest.fixture
def api(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ApiClient, str, int]]:
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
    client = ApiClient(TestClient(app))
    r = client.post("/engagements",
                    json={"client": "ACME", "primary_domain": "acme.example",
                          "scope": [{"kind": "wildcard",
                                     "pattern": "acme.example"}]},
                    headers={"Authorization": f"Bearer {token}"})
    eng_id = r.json()["id"]
    try:
        yield client, token, eng_id
    finally:
        reset_settings(None)


def _hdrs(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.integration
def test_workflow_state_shape(api) -> None:
    client, token, eng_id = api
    r = client.get(f"/engagements/{eng_id}/workflow-state",
                   headers=_hdrs(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["engagement_id"] == eng_id
    assert len(body["steps"]) == 6
    ids = [s["id"] for s in body["steps"]]
    assert ids == ["setup", "tooling", "execute", "triage",
                   "report", "finalize"]
    for s in body["steps"]:
        assert 0.0 <= s["completion"] <= 1.0
        assert "summary" in s
    stats = body["stats"]
    assert stats["scope_rules"] == 1
    assert stats["asset_count"] == 0
    assert stats["finding_count"] == 0
    assert stats["archive_configured"] is False


@pytest.mark.integration
def test_workflow_state_setup_completion(api) -> None:
    client, token, eng_id = api
    body = client.get(f"/engagements/{eng_id}/workflow-state",
                      headers=_hdrs(token)).json()
    setup = next(s for s in body["steps"] if s["id"] == "setup")
    # client + primary_domain + scope rule = all three present → 1.0
    assert setup["completion"] == 1.0


@pytest.mark.integration
def test_workflow_state_reflects_tool_policy(api) -> None:
    client, token, eng_id = api
    # Initially zero policy rows
    body = client.get(f"/engagements/{eng_id}/workflow-state",
                      headers=_hdrs(token)).json()
    tooling = next(s for s in body["steps"] if s["id"] == "tooling")
    assert tooling["completion"] == 0.0
    assert "default" in tooling["summary"]

    # Apply a preset → tooling step jumps to 1.0
    client.post(f"/engagements/{eng_id}/tool-policy/preset/no_dos",
                headers=_hdrs(token))
    body = client.get(f"/engagements/{eng_id}/workflow-state",
                      headers=_hdrs(token)).json()
    tooling = next(s for s in body["steps"] if s["id"] == "tooling")
    assert tooling["completion"] == 1.0
    assert "blocked" in tooling["summary"]


@pytest.mark.integration
def test_workflow_state_reflects_step_runs(api) -> None:
    client, token, eng_id = api
    # Seed one done step run directly
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        sr = m.StepRun(
            engagement_id=eng_id, procedure="bb", stage="stage1",
            step_id="bb.stage1.crtsh",
            mode=m.StepMode.AUTO,
            status=m.StepStatus.DONE,
        )
        s.add(sr)
    body = client.get(f"/engagements/{eng_id}/workflow-state",
                      headers=_hdrs(token)).json()
    execute = next(s for s in body["steps"] if s["id"] == "execute")
    # 1 done out of N total steps — small but > 0
    assert execute["completion"] > 0.0
    assert "1/" in execute["summary"]


@pytest.mark.integration
def test_workflow_state_404_on_unknown_engagement(api) -> None:
    client, token, _ = api
    r = client.get("/engagements/9999/workflow-state",
                   headers=_hdrs(token))
    assert r.status_code == 404
