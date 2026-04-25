"""Integration tests for the /labs JSON API.

We don't actually exercise docker — too flaky for CI and the user
might not have it installed. Instead we monkeypatch the manager
functions to return canned LabResult / LabStatus objects and assert
the API surface marshals them correctly.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token
from twisted.engine.routes import labs as labs_route
from twisted.labs import LabResult, LabState, LabStatus
from twisted.labs import manager as lm


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
def test_list_labs_returns_catalogue(api) -> None:
    client, token = api
    r = client.get("/labs", headers=_hdrs(token))
    assert r.status_code == 200
    rows = r.json()
    ids = {r["id"] for r in rows}
    assert ids == {"dvwa", "juice_shop", "wordpress", "metasploitable"}
    for row in rows:
        assert row["target_url"].startswith("http://127.0.0.1:")
        assert "practice_for" in row
        # state is one of the LabState values
        assert row["state"] in {"up", "down", "partial", "unknown"}


@pytest.mark.integration
def test_list_labs_includes_practice_step_mapping(api) -> None:
    client, token = api
    r = client.get("/labs", headers=_hdrs(token))
    wp = next(r for r in r.json() if r["id"] == "wordpress")
    assert "wp_stress.phase2.escalating" in wp["practice_for"]


@pytest.mark.integration
def test_get_one_lab_404_on_unknown(api) -> None:
    client, token = api
    r = client.get("/labs/no-such-lab", headers=_hdrs(token))
    assert r.status_code == 404


@pytest.mark.integration
def test_meta_reports_docker_availability(api) -> None:
    client, token = api
    r = client.get("/labs/_meta", headers=_hdrs(token))
    assert r.status_code == 200
    assert isinstance(r.json()["docker_available"], bool)


@pytest.mark.integration
def test_lab_up_and_down_when_docker_unavailable(api) -> None:
    client, token = api
    with patch.object(labs_route, "docker_available", return_value=False), \
         patch.object(lm, "docker_available", return_value=False):
        r = client.post("/labs/dvwa/up", json={}, headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert body["success"] is False


@pytest.mark.integration
def test_lab_up_with_mocked_success(api) -> None:
    client, token = api
    fake_status = LabStatus(spec=lm.get_lab("dvwa"), state=LabState.UP,
                             services={"twisted_dvwa-dvwa-1": "running"},
                             target_url=lm.get_lab("dvwa").target_url)
    with patch.object(labs_route, "run_up",
                      return_value=LabResult(success=True, available=True,
                                              state=LabState.UP,
                                              output="Started\n")), \
         patch.object(labs_route, "lab_status", return_value=fake_status):
        r = client.post("/labs/dvwa/up", json={"port": 28181},
                        headers=_hdrs(token))
    body = r.json()
    assert r.status_code == 200
    assert body["success"] is True
    assert body["state"] == "up"


@pytest.mark.integration
def test_lab_logs_passes_tail_argument(api) -> None:
    client, token = api
    captured = {}

    def fake_logs(spec, *, tail: int = 100):
        captured["tail"] = tail
        captured["lab"] = spec.id
        return LabResult(success=True, available=True,
                         output="line1\nline2\nline3\n")

    with patch.object(labs_route, "run_logs", side_effect=fake_logs):
        r = client.get("/labs/wordpress/logs?tail=42", headers=_hdrs(token))
    body = r.json()
    assert r.status_code == 200
    assert captured == {"lab": "wordpress", "tail": 42}
    assert "line2" in body["output"]


@pytest.mark.integration
def test_unauthenticated_labs_request_rejected(api) -> None:
    client, _ = api
    r = client.get("/labs")
    assert r.status_code == 401
