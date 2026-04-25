"""Phase 8 legacy-UI guard rails.

Three things this test enforces:

1. **No new templates.** The legacy dashboard's Jinja templates are a
   frozen set; every new HTML page belongs in ``frontend/src/pages/``,
   not ``src/twisted/web/templates/``. If this count goes up, the test
   fails with a clear "add the new page to the SPA" message. Removing
   templates is fine — just lower the expected number here too.

2. **No new legacy GET routes.** Same idea for the routes registered
   in ``engine/routes/web.py``. Operators consume the SPA at /; the
   legacy /dashboard/* surface should only ever shrink.

3. **Banner + gate dial honoured.** Verifies that ``Settings.legacy_ui``
   accepts ``enabled`` / ``banner`` / ``disabled``, normalises
   on/off/yes/no aliases, and that ``disabled`` mode actually 307s
   /dashboard/* GETs to the SPA equivalent.

When you DO retire something legacy, lower the EXPECTED_* numbers
below to match the new reality. The test is here to force the
conversation, not to forbid removal.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ApiClient
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token
from twisted.engine.legacy_gate import spa_equivalent

# Locked-in counts as of Phase 8C. Lower these when retiring legacy
# pages/routes; never raise them — that's exactly what this test
# guards against.
EXPECTED_TEMPLATE_COUNT = 15  # src/twisted/web/templates/*.html
EXPECTED_LEGACY_GET_ROUTES = 16  # @router.get(...) in routes/web.py


# ──────────────────────────── Counts ────────────────────────────


def _templates_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parents[2] / "src" / "twisted" / "web" / "templates"


def _web_routes_file() -> Path:
    here = Path(__file__).resolve()
    return here.parents[2] / "src" / "twisted" / "engine" / "routes" / "web.py"


@pytest.mark.integration
def test_legacy_template_count_does_not_grow() -> None:
    files = sorted(_templates_dir().glob("*.html"))
    actual = len(files)
    assert actual <= EXPECTED_TEMPLATE_COUNT, (
        f"\nLegacy Jinja templates went from {EXPECTED_TEMPLATE_COUNT} → {actual}.\n"
        f"New files: {[f.name for f in files]}\n\n"
        f"Phase 8 retired the legacy dashboard. New UI work belongs in\n"
        f"`frontend/src/pages/`, not `src/twisted/web/templates/`. If this\n"
        f"new template was a mistake, delete it. If you genuinely meant to\n"
        f"add it, raise EXPECTED_TEMPLATE_COUNT here AND open an issue\n"
        f"explaining why the legacy surface needs to grow."
    )


@pytest.mark.integration
def test_legacy_get_route_count_does_not_grow() -> None:
    """Coarse but effective: count `@router.get(` occurrences in
    routes/web.py. Each one is a legacy HTML or HTMX-fragment GET."""
    text = _web_routes_file().read_text(encoding="utf-8")
    actual = text.count("@router.get(")
    assert actual <= EXPECTED_LEGACY_GET_ROUTES, (
        f"\nLegacy /dashboard/* GET routes went from {EXPECTED_LEGACY_GET_ROUTES}"
        f" → {actual}.\n\n"
        f"New page handlers belong in the SPA (`frontend/src/pages/` +"
        f" `App.tsx`).\n"
        f"If you genuinely had to extend the legacy surface, lower this"
        f" expected\n"
        f"count back to the prior value, raise EXPECTED_LEGACY_GET_ROUTES,"
        f" and\n"
        f"document why in a commit message."
    )


# ──────────────────────────── SPA equivalent mapping ────────────────────────────


@pytest.mark.parametrize("legacy,expected", [
    ("/dashboard/", "/"),
    ("/dashboard", "/"),
    ("/dashboard/workers", "/workers"),
    ("/dashboard/labs", "/labs"),
    ("/dashboard/labs/dvwa/logs", "/labs"),
    ("/dashboard/training", "/training"),
    ("/dashboard/training/bb.stage1.crtsh", "/training"),
    ("/dashboard/procedures", "/procedures"),
    ("/dashboard/engagements/42", "/engagements/42"),
    ("/dashboard/engagements/42/findings", "/engagements/42/findings"),
    ("/dashboard/engagements/42/findings/7", "/engagements/42/findings/7"),
    ("/dashboard/engagements/42/findings/7/redact", "/engagements/42/findings/7"),
    ("/dashboard/engagements/42/assets", "/engagements/42/assets"),
    ("/dashboard/engagements/42/runs", "/engagements/42/runs"),
    ("/dashboard/something/totally/unmapped", "/"),
])
def test_spa_equivalent(legacy: str, expected: str) -> None:
    assert spa_equivalent(legacy) == expected


# ──────────────────────────── Settings normalisation ────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    ("enabled", "enabled"),
    ("banner", "banner"),
    ("disabled", "disabled"),
    ("ENABLED", "enabled"),
    ("on", "enabled"),
    ("off", "disabled"),
    ("yes", "enabled"),
    ("no", "disabled"),
    ("true", "enabled"),
    ("false", "disabled"),
    ("1", "enabled"),
    ("0", "disabled"),
    ("", "banner"),         # default
    ("garbage", "banner"),  # unknown → safe default
])
def test_legacy_ui_setting_normalises(raw: str, expected: str,
                                       monkeypatch: pytest.MonkeyPatch,
                                       tmp_path: Path) -> None:
    monkeypatch.setenv("TWISTED_LEGACY_UI", raw)
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "tok"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{tmp_path}/db.sqlite")
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    s = Settings()
    assert s.legacy_ui == expected


# ──────────────────────────── End-to-end gate ────────────────────────────


@pytest.fixture
def app_in_mode(tmp_path: Path,
                monkeypatch: pytest.MonkeyPatch
                ) -> Iterator[ApiClient]:
    data = tmp_path / "data"
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(data))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "tok"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{data}/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    ensure_token(s)
    client = ApiClient(TestClient(app, follow_redirects=False))
    try:
        yield client
    finally:
        reset_settings(None)


@pytest.mark.integration
def test_disabled_mode_redirects_dashboard_get(app_in_mode,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TWISTED_LEGACY_UI", "disabled")
    reset_settings(None)  # force re-read on next get_settings() call
    r = app_in_mode.get("/dashboard/engagements/1")
    assert r.status_code == 307
    assert r.headers["location"] == "/engagements/1"


@pytest.mark.integration
def test_disabled_mode_does_not_block_post_login(app_in_mode,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    """Disabling the legacy UI must NOT break the SPA's auth flow —
    POST /login still works because the SPA still calls it to set
    the cookie."""
    monkeypatch.setenv("TWISTED_LEGACY_UI", "disabled")
    reset_settings(None)
    # Without a real token, login fails authentication but isn't gated
    r = app_in_mode.post("/login", data={"token": "wrong"})
    # 401 (bad token) or 200 with form re-render — both prove the gate
    # didn't hijack the request with a 307 redirect.
    assert r.status_code != 307


@pytest.mark.integration
def test_banner_mode_renders_banner(app_in_mode,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TWISTED_LEGACY_UI", "banner")
    reset_settings(None)
    r = app_in_mode.get("/login")
    assert r.status_code == 200
    assert "Legacy UI" in r.text
    assert "Switch to the new UI" in r.text


@pytest.mark.integration
def test_enabled_mode_no_banner(app_in_mode,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TWISTED_LEGACY_UI", "enabled")
    reset_settings(None)
    r = app_in_mode.get("/login")
    assert r.status_code == 200
    assert "Switch to the new UI" not in r.text


@pytest.mark.integration
def test_default_is_banner_when_env_unset(tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """If TWISTED_LEGACY_UI is unset, the default is `banner` —
    legacy keeps working but every page nudges the user to the SPA."""
    monkeypatch.delenv("TWISTED_LEGACY_UI", raising=False)
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "d"))
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "tok"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{tmp_path}/db.sqlite")
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    s = Settings()
    assert s.legacy_ui == "banner"
