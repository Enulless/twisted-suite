"""Regression tests for the /api/* cookie-auth path.

Phase 8A originally only accepted ``Authorization: Bearer`` on the
JSON API, which broke the SPA loop after POST /login (the cookie
got set but /api/engagements still returned 401, sending the user
back to /login forever). The fix in engine.auth.require_token now
accepts EITHER the header OR the dashboard's ``twisted_token``
cookie.

These tests pin both paths so a future refactor can't quietly
regress to header-only and break the SPA again.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ApiClient
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import SESSION_COOKIE_NAME, ensure_token


@pytest.fixture
def api(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ApiClient, str]]:
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
    client = ApiClient(TestClient(app, follow_redirects=False))
    try:
        yield client, token
    finally:
        reset_settings(None)


@pytest.mark.integration
def test_api_accepts_bearer_header(api) -> None:
    client, token = api
    r = client.get("/engagements", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


@pytest.mark.integration
def test_api_accepts_session_cookie(api) -> None:
    """The exact SPA flow: POST /login sets the cookie; subsequent
    /api/* calls authenticate from it without any Authorization header."""
    client, token = api
    r = client.post("/login", data={"token": token, "next": "/"})
    assert r.status_code == 303
    cookie = r.cookies.get(SESSION_COOKIE_NAME)
    assert cookie == token
    # NO Authorization header — only the cookie
    r = client.get("/engagements", cookies={SESSION_COOKIE_NAME: cookie})
    assert r.status_code == 200, r.text


@pytest.mark.integration
def test_api_rejects_missing_credentials(api) -> None:
    client, _ = api
    r = client.get("/engagements")
    assert r.status_code == 401


@pytest.mark.integration
def test_api_rejects_wrong_token_in_cookie(api) -> None:
    client, _ = api
    r = client.get("/engagements",
                   cookies={SESSION_COOKIE_NAME: "obviously-wrong"})
    assert r.status_code == 401


@pytest.mark.integration
def test_api_rejects_wrong_token_in_header(api) -> None:
    client, _ = api
    r = client.get("/engagements",
                   headers={"Authorization": "Bearer obviously-wrong"})
    assert r.status_code == 401


@pytest.mark.integration
def test_api_cookie_auth_works_for_protected_endpoints(api) -> None:
    """End-to-end: cookie auth lets the SPA hit every router that
    matters (engagements, workers, labs, training, tool-policy)."""
    client, token = api
    r = client.post("/login", data={"token": token, "next": "/"})
    cookie = {SESSION_COOKIE_NAME: r.cookies.get(SESSION_COOKIE_NAME)}
    for path in [
        "/engagements",
        "/workers",
        "/labs",
        "/training",
        "/procedures",
    ]:
        r = client.get(path, cookies=cookie)
        assert r.status_code == 200, f"{path} → {r.status_code}: {r.text[:200]}"
