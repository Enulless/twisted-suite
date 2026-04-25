"""Phase 5: HTML dashboard smoke + auth tests.

Covers:
- /login GET renders, with the local token auto-filled when
  available (single-user case).
- /login POST rejects bad tokens (401, login form re-rendered).
- /login POST accepts the engine token and sets the session cookie.
- Unauthenticated dashboard requests redirect (303) to /login?next=...
- All dashboard pages render with both bearer-header and cookie auth.
- /static/twisted.css is served by the StaticFiles mount.
- Index, workers, procedures, engagement detail, assets, findings
  kanban, finding detail, and runs pages all return 200 and contain
  expected content from the seed data.
- The CVSS-calculator HTMX endpoint computes a score, persists it,
  and renders a fragment with the severity pill.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from twisted.core import models as m
from twisted.core.db import session_scope
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token


@pytest.fixture
def dash_app(tmp_path: Path,
             monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str, Settings]]:
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
    # follow_redirects=False so we can assert the 303 redirect chain
    # explicitly when testing auth.
    client = TestClient(app, follow_redirects=False)
    try:
        yield client, token, s
    finally:
        reset_settings(None)


def _seed(app_state, *, with_finding: bool = True) -> dict[str, int]:
    """Seed one engagement, one worker, one asset, one finding, one
    step run via the engine state's session factory."""
    factory = app_state.session_factory
    ids: dict[str, int] = {}
    with session_scope(factory) as s:
        eng = m.Engagement(client="ACME", primary_domain="acme.example",
                           status=m.EngagementStatus.ACTIVE)
        eng.scope_rules.append(m.ScopeRule(kind=m.ScopeKind.WILDCARD,
                                            pattern="acme.example"))
        s.add(eng)
        s.flush()
        ids["engagement_id"] = eng.id

        asset = m.Asset(engagement_id=eng.id, host="api.acme.example",
                        ip="192.0.2.1", env_type="staging",
                        in_scope=True, source="crt.sh", risk_total=14)
        asset.ports.append(m.Port(asset_id=0, port=443, proto="tcp",
                                   service="https"))
        asset.techs.append(m.Technology(asset_id=0, name="Apache",
                                         version="2.4.41", source="banner"))
        asset.cves.append(m.CVE(asset_id=0, cve_id="CVE-2021-44790",
                                 cvss_score=9.8, severity="CRITICAL",
                                 summary="Apache mod_lua heap buffer overflow"))
        s.add(asset)
        s.flush()
        ids["asset_id"] = asset.id

        worker = m.Worker(id="wsl-test-1", hostname="wsl-host",
                          os="linux",
                          capabilities=["network", "dig", "openssl"],
                          status=m.WorkerStatus.ONLINE,
                          last_seen=datetime.now(UTC))
        s.add(worker)

        if with_finding:
            f = m.Finding(engagement_id=eng.id, asset_id=asset.id,
                          title="Reflected XSS in /search",
                          severity=m.FindingSeverity.HIGH,
                          cwe="CWE-79", status=m.FindingStatus.DRAFT,
                          description="GET /search?q=<script>... reflected.",
                          remediation="HTML-encode template output.")
            s.add(f)
            s.flush()
            ids["finding_id"] = f.id

        sr = m.StepRun(engagement_id=eng.id, procedure="bb", stage="stage1",
                       step_id="bb.stage1.crtsh",
                       mode=m.StepMode.AUTO,
                       status=m.StepStatus.DONE,
                       worker_id="wsl-test-1",
                       output_summary="crt.sh: 12 subdomains harvested")
        s.add(sr)

    return ids


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────── Static + login ────────────────────────────


@pytest.mark.integration
def test_static_css_served(dash_app) -> None:
    client, _, _ = dash_app
    r = client.get("/static/twisted.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert ".kanban" in r.text  # sentinel: the file actually loaded


@pytest.mark.integration
def test_login_form_renders_with_prefilled_token(dash_app) -> None:
    client, token, _ = dash_app
    r = client.get("/login")
    assert r.status_code == 200
    assert "<title>Login" in r.text
    # The local token file exists for the dashboard process, so the form
    # should pre-fill it (single-user convenience).
    assert f'value="{token}"' in r.text


@pytest.mark.integration
def test_login_rejects_bad_token(dash_app) -> None:
    client, _, _ = dash_app
    r = client.post("/login", data={"token": "obviously-wrong"})
    assert r.status_code == 401
    assert "Invalid token" in r.text


@pytest.mark.integration
def test_login_sets_cookie_and_redirects(dash_app) -> None:
    client, token, _ = dash_app
    r = client.post("/login", data={"token": token, "next": "/dashboard/workers"})
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard/workers"
    cookie = r.cookies.get("twisted_token")
    assert cookie == token


@pytest.mark.integration
def test_login_blocks_open_redirect(dash_app) -> None:
    client, token, _ = dash_app
    r = client.post("/login",
                    data={"token": token, "next": "https://evil.example/"})
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard/"  # rewritten to dashboard root


@pytest.mark.integration
def test_unauthenticated_dashboard_redirects_to_login(dash_app) -> None:
    client, _, _ = dash_app
    r = client.get("/dashboard/")
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


@pytest.mark.integration
def test_root_serves_spa_or_redirects_to_dashboard(dash_app) -> None:
    """When the SPA is built (frontend/dist/ present), GET / returns
    the SPA shell. When it isn't, GET / 307-redirects to /dashboard/.
    Both are valid Phase 8A states; this test accepts either."""
    client, _, _ = dash_app
    r = client.get("/")
    if r.status_code == 200:
        # SPA mode: index.html with the React mount point
        assert 'id="root"' in r.text
    else:
        assert r.status_code == 307
        assert r.headers["location"] == "/dashboard/"


@pytest.mark.integration
def test_logout_clears_cookie(dash_app) -> None:
    client, token, _ = dash_app
    client.post("/login", data={"token": token})
    r = client.get("/logout")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    # Cookie cleared (max-age=0 or expires in the past)
    set_cookie = r.headers.get("set-cookie", "")
    assert "twisted_token=" in set_cookie
    assert "Max-Age=0" in set_cookie or 'expires=' in set_cookie.lower()


# ──────────────────────────── Dashboard pages ────────────────────────────


@pytest.mark.integration
def test_index_renders_engagements_and_workers(dash_app) -> None:
    client, token, _ = dash_app
    _seed(client.app.state.engine_state, with_finding=False)
    r = client.get("/dashboard/", headers=_bearer(token))
    assert r.status_code == 200
    assert "ACME" in r.text
    assert "wsl-test-1" in r.text
    assert "status-online" in r.text


@pytest.mark.integration
def test_workers_page_renders(dash_app) -> None:
    client, token, _ = dash_app
    _seed(client.app.state.engine_state, with_finding=False)
    r = client.get("/dashboard/workers", headers=_bearer(token))
    assert r.status_code == 200
    assert "wsl-test-1" in r.text
    assert "openssl" in r.text  # capabilities rendered


@pytest.mark.integration
def test_workers_htmx_fragment(dash_app) -> None:
    client, token, _ = dash_app
    _seed(client.app.state.engine_state, with_finding=False)
    r = client.get("/htmx/workers", headers=_bearer(token))
    assert r.status_code == 200
    assert "1/1 online" in r.text
    assert 'hx-get="/htmx/workers"' in r.text  # self-replacing


@pytest.mark.integration
def test_procedures_page_lists_loaded_procedures(dash_app) -> None:
    client, token, _ = dash_app
    r = client.get("/dashboard/procedures", headers=_bearer(token))
    assert r.status_code == 200
    # All three packaged procedures should be present
    assert "bb" in r.text
    assert "wp_stress" in r.text
    assert "wifi" in r.text


@pytest.mark.integration
def test_engagement_detail_page(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.get(f"/dashboard/engagements/{ids['engagement_id']}",
                   headers=_bearer(token))
    assert r.status_code == 200
    assert "ACME" in r.text
    assert "acme.example" in r.text  # primary_domain + scope rule
    # Procedure stages section present
    assert "Stage progress" in r.text


@pytest.mark.integration
def test_assets_page_with_risk_tier(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.get(f"/dashboard/engagements/{ids['engagement_id']}/assets",
                   headers=_bearer(token))
    assert r.status_code == 200
    assert "api.acme.example" in r.text
    assert "Apache" in r.text
    assert "443" in r.text
    # risk_total=14 → "high" tier per risk_scoring.tier()
    assert "risk-high" in r.text
    assert "1 in scope" in r.text


@pytest.mark.integration
def test_findings_kanban_buckets(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.get(f"/dashboard/engagements/{ids['engagement_id']}/findings",
                   headers=_bearer(token))
    assert r.status_code == 200
    assert "Reflected XSS" in r.text
    # Kanban columns present in severity order
    text = r.text
    assert text.index("Critical") < text.index("High") < text.index("Medium")
    # Our seeded finding lives in the "high" column with the sev-high card
    assert 'class="card sev-high"' in r.text


@pytest.mark.integration
def test_finding_detail_with_cvss_calculator(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.get(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}",
        headers=_bearer(token),
    )
    assert r.status_code == 200
    assert "Reflected XSS" in r.text
    assert "CVSS Calculator" in r.text
    # HTMX form posts to the per-finding cvss endpoint
    assert (f'hx-post="/dashboard/engagements/{ids["engagement_id"]}'
            f'/findings/{ids["finding_id"]}/cvss"') in r.text


@pytest.mark.integration
def test_runs_page_lists_step_runs(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.get(f"/dashboard/engagements/{ids['engagement_id']}/runs",
                   headers=_bearer(token))
    assert r.status_code == 200
    assert "bb.stage1.crtsh" in r.text
    assert "crt.sh: 12 subdomains" in r.text
    assert "wsl-test-1" in r.text


@pytest.mark.integration
def test_engagement_dashboard_404(dash_app) -> None:
    client, token, _ = dash_app
    r = client.get("/dashboard/engagements/9999", headers=_bearer(token))
    assert r.status_code == 404


# ──────────────────────────── CVSS HTMX endpoint ────────────────────────────


@pytest.mark.integration
def test_cvss_calculator_computes_and_persists(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    # Critical 10.0 vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    r = client.post(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/cvss",
        data={"AV": "N", "AC": "L", "PR": "N", "UI": "N",
              "S": "C", "C": "H", "I": "H", "A": "H"},
        headers=_bearer(token),
    )
    assert r.status_code == 200
    assert "Score:" in r.text
    assert "Critical" in r.text
    assert "10.0" in r.text
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in r.text

    # Persisted to the finding row
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, ids["finding_id"])
        assert f.cvss_score == 10.0
        assert f.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


@pytest.mark.integration
def test_cvss_calculator_rejects_missing_metric(dash_app) -> None:
    client, token, _ = dash_app
    ids = _seed(client.app.state.engine_state)
    r = client.post(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/cvss",
        data={"AV": "N", "AC": "L"},  # missing PR/UI/S/C/I/A
        headers=_bearer(token),
    )
    assert r.status_code == 400
    assert "every base metric" in r.text


# ──────────────────────────── Cookie-only auth flow ────────────────────────────


@pytest.mark.integration
def test_full_login_then_browse_via_cookie(dash_app) -> None:
    """End-to-end browser flow: GET /login → POST /login → cookie set →
    every subsequent dashboard request authenticates from the cookie
    with no Authorization header."""
    client, token, _ = dash_app
    _seed(client.app.state.engine_state, with_finding=False)

    # Unauthenticated → redirect
    r = client.get("/dashboard/")
    assert r.status_code == 303

    # Login (sets the cookie on the TestClient session jar)
    r = client.post("/login", data={"token": token})
    assert r.status_code == 303
    assert r.cookies.get("twisted_token") == token

    # The TestClient persists cookies between calls via its own jar.
    # Send subsequent requests with the cookie pinned (TestClient
    # doesn't forward Set-Cookie automatically across redirects when
    # follow_redirects=False, so we send it explicitly).
    cookies = {"twisted_token": token}
    r = client.get("/dashboard/", cookies=cookies)
    assert r.status_code == 200
    assert "ACME" in r.text

    r = client.get("/dashboard/workers", cookies=cookies)
    assert r.status_code == 200
    assert "wsl-test-1" in r.text
