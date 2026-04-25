"""Integration tests for the finalize endpoints + dashboard buttons."""

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
        monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str, Path]]:
    data = tmp_path / "data"
    archive = tmp_path / "onedrive"
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(data))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", str(archive))
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{data}/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    token = ensure_token(s)
    client = TestClient(app, follow_redirects=False)
    try:
        yield client, token, archive
    finally:
        reset_settings(None)


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _seed(app_state, tmp_path: Path) -> dict[str, int]:
    factory = app_state.session_factory
    ids: dict[str, int] = {}
    src = tmp_path / "shot.png"
    redacted = tmp_path / "redacted_shot.png"
    src.write_bytes(b"\x89PNG\r\n\x1a\noriginal-bytes")
    redacted.write_bytes(b"\x89PNG\r\n\x1a\nredacted-bytes")
    with session_scope(factory) as s:
        eng = m.Engagement(client="ACME", primary_domain="acme.example",
                           status=m.EngagementStatus.ACTIVE)
        s.add(eng)
        s.flush()
        ids["engagement_id"] = eng.id
        f = m.Finding(engagement_id=eng.id, title="XSS",
                      severity=m.FindingSeverity.HIGH,
                      status=m.FindingStatus.DRAFT)
        s.add(f)
        s.flush()
        ids["finding_id"] = f.id
        s.add(m.Evidence(
            engagement_id=eng.id, finding_id=f.id,
            kind=m.EvidenceKind.SCREENSHOT,
            path=str(src), redacted_path=str(redacted),
            sha256="x" * 64, host="wsl",
        ))
    return ids


@pytest.mark.integration
def test_archive_status_when_configured(api) -> None:
    client, token, archive = api
    _seed(client.app.state.engine_state, archive.parent)
    eng_id = 1  # only one engagement
    r = client.get(f"/engagements/{eng_id}/archive-status",
                   headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert "onedrive" in body["archive_root"]
    assert "engagements/acme/reports" in body["reports_dir"]


@pytest.mark.integration
def test_finalize_finding_archives_redacted_evidence(api, tmp_path: Path) -> None:
    client, token, archive = api
    ids = _seed(client.app.state.engine_state, tmp_path)
    r = client.post(
        f"/engagements/{ids['engagement_id']}/findings/{ids['finding_id']}/finalize",
        headers=_hdrs(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert len(body["archived_paths"]) == 1
    archived = Path(body["archived_paths"][0])
    assert archived.exists()
    # Redacted bytes (not original) — that's the whole point
    assert archived.read_bytes() == b"\x89PNG\r\n\x1a\nredacted-bytes"
    # Finding flipped to REPORTED + finalized_at stamped
    factory = client.app.state.engine_state.session_factory
    with session_scope(factory) as s:
        f = s.get(m.Finding, ids["finding_id"])
        assert f.status == m.FindingStatus.REPORTED
        assert f.finalized_at is not None
        ev = s.execute(
            select(m.Evidence).where(m.Evidence.finding_id == ids["finding_id"])
        ).scalars().first()
        assert ev.finalized_at is not None


@pytest.mark.integration
def test_finalize_report_copies_files(api, tmp_path: Path) -> None:
    client, token, archive = api
    _seed(client.app.state.engine_state, tmp_path)
    eng_id = 1
    rpt = tmp_path / "report.html"
    rpt.write_text("<html>final</html>")
    r = client.post(
        f"/engagements/{eng_id}/finalize-report",
        json={"paths": [str(rpt)]},
        headers=_hdrs(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert len(body["archived_paths"]) == 1
    target = Path(body["archived_paths"][0])
    assert target.exists()
    assert "engagements/acme/reports" in str(target)


@pytest.mark.integration
def test_finalize_finding_404_when_missing(api) -> None:
    client, token, _ = api
    _seed(client.app.state.engine_state, Path("/tmp"))
    r = client.post("/engagements/1/findings/999/finalize",
                    headers=_hdrs(token))
    assert r.status_code == 404


@pytest.mark.integration
def test_archive_status_when_unset(tmp_path: Path,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    # Spin up a fresh app where TWISTED_ARCHIVE_ROOT is empty.
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "tok"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{tmp_path}/data/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    token = ensure_token(s)
    c = TestClient(app)
    # Need an engagement
    r = c.post("/engagements", json={"client": "X"}, headers=_hdrs(token))
    eng_id = r.json()["id"]
    r = c.get(f"/engagements/{eng_id}/archive-status", headers=_hdrs(token))
    assert r.status_code == 200
    assert r.json()["configured"] is False
    reset_settings(None)
