"""Phase 7 dashboard tests: labs control panel, finalize button,
practice button, redact form."""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select

from twisted.core import models as m
from twisted.core.db import session_scope
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token
from twisted.engine.routes import web as web_route
from twisted.labs import LabResult, LabState, LabStatus
from twisted.labs import manager as lm


@pytest.fixture
def dash(tmp_path: Path,
         monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str, Path]]:
    data = tmp_path / "data"
    archive = tmp_path / "archive"
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(data))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", str(archive))
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "tok"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{data}/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    token = ensure_token(s)
    client = TestClient(app, follow_redirects=False)
    try:
        yield client, token, tmp_path
    finally:
        reset_settings(None)


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _seed_engagement_with_finding(app_state, tmp_path: Path) -> dict:
    factory = app_state.session_factory
    src = tmp_path / "shot.png"
    redacted = tmp_path / "redacted_shot.png"
    src.write_bytes(b"\x89PNG\r\n\x1a\noriginal")
    redacted.write_bytes(b"\x89PNG\r\n\x1a\nredacted")
    with session_scope(factory) as s:
        e = m.Engagement(client="ACME", primary_domain="acme.example",
                         status=m.EngagementStatus.ACTIVE)
        s.add(e)
        s.flush()
        f = m.Finding(engagement_id=e.id, title="Reflected XSS",
                      severity=m.FindingSeverity.HIGH,
                      status=m.FindingStatus.DRAFT)
        s.add(f)
        s.flush()
        s.add(m.Evidence(
            engagement_id=e.id, finding_id=f.id,
            kind=m.EvidenceKind.SCREENSHOT,
            path=str(src), redacted_path=str(redacted),
            sha256="x" * 64, host="wsl",
        ))
        return {"engagement_id": e.id, "finding_id": f.id}


# ──────────────────────────── Labs control panel ────────────────────────────


@pytest.mark.integration
def test_labs_index_renders_all_four(dash) -> None:
    client, token, _ = dash
    r = client.get("/dashboard/labs", headers=_hdrs(token))
    assert r.status_code == 200
    for lab in ("Damn Vulnerable", "Juice Shop", "WordPress", "Metasploitable"):
        assert lab in r.text


@pytest.mark.integration
def test_labs_index_warns_when_docker_missing(dash,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    client, token, _ = dash
    monkeypatch.setattr(web_route, "docker_available", lambda: False)
    r = client.get("/dashboard/labs", headers=_hdrs(token))
    assert r.status_code == 200
    assert "Docker isn't installed" in r.text


@pytest.mark.integration
def test_lab_up_fragment_with_mocked_success(dash) -> None:
    client, token, _ = dash
    fake = LabResult(success=True, available=True, state=LabState.UP,
                     output="ok")
    with patch.object(web_route, "run_lab_up", return_value=fake):
        r = client.post("/dashboard/labs/dvwa/up", headers=_hdrs(token))
    assert r.status_code == 200
    assert "dvwa brought up" in r.text
    assert "status-online" in r.text


@pytest.mark.integration
def test_lab_down_fragment_with_mocked_success(dash) -> None:
    client, token, _ = dash
    fake = LabResult(success=True, available=True, state=LabState.DOWN,
                     output="bye")
    with patch.object(web_route, "take_lab_down", return_value=fake):
        r = client.post("/dashboard/labs/dvwa/down", headers=_hdrs(token))
    assert r.status_code == 200
    assert "torn down" in r.text


@pytest.mark.integration
def test_lab_logs_view(dash) -> None:
    client, token, _ = dash
    fake_logs = LabResult(success=True, available=True, output="line1\nline2\n")
    fake_status = LabStatus(spec=lm.get_lab("dvwa"), state=LabState.UP,
                             target_url=lm.get_lab("dvwa").target_url)
    with patch.object(web_route, "run_lab_logs", return_value=fake_logs), \
         patch.object(web_route, "get_lab_status", return_value=fake_status):
        r = client.get("/dashboard/labs/dvwa/logs?tail=50", headers=_hdrs(token))
    assert r.status_code == 200
    assert "line1" in r.text
    assert "line2" in r.text


# ──────────────────────────── Finalize button ────────────────────────────


@pytest.mark.integration
def test_finalize_finding_fragment(dash) -> None:
    client, token, tmp_path = dash
    ids = _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    r = client.post(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/finalize",
        headers=_hdrs(token),
    )
    assert r.status_code == 200
    assert "Marked final" in r.text
    assert "REPORTED" in r.text
    # Persisted to the DB
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, ids["finding_id"])
        assert f.status == m.FindingStatus.REPORTED
        assert f.finalized_at is not None


# ──────────────────────────── Practice on lab ────────────────────────────


@pytest.mark.integration
def test_practice_button_renders_on_training_page(dash) -> None:
    """Training detail page surfaces the 'Practice on the lab' section
    for steps that map to a registered lab."""
    client, token, tmp_path = dash
    _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    r = client.get("/dashboard/training/wp_stress.phase2.escalating",
                   headers=_hdrs(token))
    assert r.status_code == 200
    assert "Practice on the lab" in r.text
    assert "WordPress" in r.text


@pytest.mark.integration
def test_practice_button_queues_step_against_lab(dash) -> None:
    client, token, tmp_path = dash
    ids = _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    fake_status = LabStatus(spec=lm.get_lab("wordpress"), state=LabState.UP,
                             target_url=lm.get_lab("wordpress").target_url)
    with patch.object(web_route, "get_lab_status", return_value=fake_status):
        r = client.post(
            "/dashboard/training/wp_stress.phase2.escalating/practice",
            data={"engagement_id": str(ids["engagement_id"])},
            headers=_hdrs(token),
        )
    assert r.status_code == 200, r.text
    assert "Queued" in r.text
    assert "wp_stress.phase2.escalating" in r.text
    # A step_run row was created
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        runs = s.execute(
            select(m.StepRun).where(
                m.StepRun.step_id == "wp_stress.phase2.escalating"
            )
        ).scalars().all()
        assert len(runs) == 1
        assert runs[0].engagement_id == ids["engagement_id"]
        # Params resolved against the lab's target URL
        assert runs[0].params and "host" in runs[0].params


@pytest.mark.integration
def test_practice_button_400_without_engagement(dash) -> None:
    client, token, _ = dash
    r = client.post(
        "/dashboard/training/wp_stress.phase2.escalating/practice",
        data={},  # no engagement_id
        headers=_hdrs(token),
    )
    assert r.status_code == 400


# ──────────────────────────── Redact ────────────────────────────


def _png_bytes(width: int = 60, height: int = 40,
               color: tuple[int, int, int] = (200, 50, 50)) -> bytes:
    img = Image.new("RGB", (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.mark.integration
def test_redact_form_renders(dash) -> None:
    client, token, tmp_path = dash
    ids = _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    r = client.get(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/redact",
        headers=_hdrs(token),
    )
    assert r.status_code == 200
    assert "redact" in r.text.lower()
    assert 'id="redact-canvas"' in r.text
    assert 'src="/static/redact.js"' in r.text


@pytest.mark.integration
def test_redact_submit_creates_evidence_row(dash) -> None:
    client, token, tmp_path = dash
    ids = _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    files = {"image": ("test.png", _png_bytes(), "image/png")}
    r = client.post(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/redact",
        files=files,
        data={"rectangles": '[{"x":10,"y":5,"width":20,"height":15}]'},
        headers=_hdrs(token),
    )
    assert r.status_code == 303
    assert "/findings/" in r.headers["location"]
    # Evidence row added (the seed function added one already; redact adds another)
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        rows = s.execute(
            select(m.Evidence).where(m.Evidence.finding_id == ids["finding_id"])
        ).scalars().all()
        assert len(rows) == 2
        # The new row has the redacted_path populated and lives under
        # the engagement's evidence/raw/ tree.
        new_rows = [r for r in rows if "redacted_" in (r.redacted_path or "")
                    and "finding{}_".format(ids["finding_id"]) in r.path]
        assert new_rows
        ev = new_rows[0]
        assert Path(ev.redacted_path).exists()
        assert ev.kind == m.EvidenceKind.SCREENSHOT
        assert "rectangles" in (ev.note or "")


@pytest.mark.integration
def test_redact_submit_rejects_invalid_rect_json(dash) -> None:
    client, token, tmp_path = dash
    ids = _seed_engagement_with_finding(client.app.state.engine_state, tmp_path)
    files = {"image": ("x.png", _png_bytes(), "image/png")}
    r = client.post(
        f"/dashboard/engagements/{ids['engagement_id']}"
        f"/findings/{ids['finding_id']}/redact",
        files=files,
        data={"rectangles": "not-json-at-all"},
        headers=_hdrs(token),
    )
    assert r.status_code == 400
    assert "Invalid rectangles" in r.text


@pytest.mark.integration
def test_labs_nav_link_present(dash) -> None:
    client, token, _ = dash
    r = client.get("/dashboard/", headers=_hdrs(token))
    assert r.status_code == 200
    assert 'href="/dashboard/labs"' in r.text
