"""Integration tests for the /tool-policy API + enforcement at /steps/run."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import ApiClient
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
    # Seed an engagement
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


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────── GET / inventory ────────────────────────────


@pytest.mark.integration
def test_get_policy_empty_by_default(api) -> None:
    client, token, eng_id = api
    r = client.get(f"/engagements/{eng_id}/tool-policy",
                   headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body["engagement_id"] == eng_id
    assert body["rows"] == []
    assert body["steps_blocked"] == []
    assert body["capabilities_blocked"] == []
    assert "open_bug_bounty" in body["presets_available"]


@pytest.mark.integration
def test_inventory_lists_every_step_and_capability(api) -> None:
    client, token, eng_id = api
    r = client.get(f"/engagements/{eng_id}/tool-policy/inventory",
                   headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body["engagement_id"] == eng_id
    # Sanity: bb.stage1.crtsh is in the catalog and starts allowed
    crtsh = next(s for s in body["steps"]
                 if s["step_id"] == "bb.stage1.crtsh")
    assert crtsh["allowed"] is True
    assert crtsh["block_reason"] is None
    # wrk capability is in the catalog
    wrk = next(c for c in body["capabilities"] if c["capability"] == "wrk")
    assert wrk["allowed"] is True
    assert wrk["step_count"] >= 1


@pytest.mark.integration
def test_unauthenticated_rejected(api) -> None:
    client, _, eng_id = api
    r = client.get(f"/engagements/{eng_id}/tool-policy")
    assert r.status_code == 401


@pytest.mark.integration
def test_404_when_engagement_missing(api) -> None:
    client, token, _ = api
    r = client.get("/engagements/99999/tool-policy", headers=_hdrs(token))
    assert r.status_code == 404


# ──────────────────────────── PUT step / capability ────────────────────────────


@pytest.mark.integration
def test_toggle_step_persists(api) -> None:
    client, token, eng_id = api
    r = client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.stage4.nmap_full",
        json={"allowed": False, "note": "no aggressive scans per RoE"},
        headers=_hdrs(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is False
    assert "no aggressive" in r.json()["note"]
    # Snapshot reflects it
    r = client.get(f"/engagements/{eng_id}/tool-policy",
                   headers=_hdrs(token))
    assert "bb.stage4.nmap_full" in r.json()["steps_blocked"]


@pytest.mark.integration
def test_toggle_step_404_on_unknown_step(api) -> None:
    client, token, eng_id = api
    r = client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.fake.step",
        json={"allowed": False},
        headers=_hdrs(token),
    )
    assert r.status_code == 404


@pytest.mark.integration
def test_toggle_capability_persists(api) -> None:
    client, token, eng_id = api
    r = client.put(
        f"/engagements/{eng_id}/tool-policy/capability/wrk",
        json={"allowed": False, "note": "no DoS"},
        headers=_hdrs(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target_kind"] == "capability"
    assert body["target_value"] == "wrk"
    assert body["allowed"] is False


@pytest.mark.integration
def test_toggle_unknown_capability_400(api) -> None:
    client, token, eng_id = api
    r = client.put(
        f"/engagements/{eng_id}/tool-policy/capability/not-a-real-cap",
        json={"allowed": False},
        headers=_hdrs(token),
    )
    assert r.status_code == 400


@pytest.mark.integration
def test_toggle_idempotent_via_upsert(api) -> None:
    client, token, eng_id = api
    for allowed in (False, True, False):
        client.put(
            f"/engagements/{eng_id}/tool-policy/capability/wrk",
            json={"allowed": allowed, "note": f"set to {allowed}"},
            headers=_hdrs(token),
        )
    snap = client.get(f"/engagements/{eng_id}/tool-policy",
                      headers=_hdrs(token)).json()
    wrk_rows = [r for r in snap["rows"]
                if r["target_kind"] == "capability"
                and r["target_value"] == "wrk"]
    assert len(wrk_rows) == 1
    assert wrk_rows[0]["allowed"] is False  # last write wins


# ──────────────────────────── Presets ────────────────────────────


@pytest.mark.integration
def test_apply_no_dos_preset(api) -> None:
    client, token, eng_id = api
    r = client.post(f"/engagements/{eng_id}/tool-policy/preset/no_dos",
                    headers=_hdrs(token))
    assert r.status_code == 200
    body = r.json()
    assert body["preset"] == "no_dos"
    assert "wrk" in body["capability_blocks"]
    assert any("escalating" in s for s in body["step_blocks"])


@pytest.mark.integration
def test_apply_open_bug_bounty_clears_existing(api) -> None:
    client, token, eng_id = api
    # Seed a block first
    client.put(
        f"/engagements/{eng_id}/tool-policy/capability/wrk",
        json={"allowed": False},
        headers=_hdrs(token),
    )
    # Apply the open preset
    r = client.post(
        f"/engagements/{eng_id}/tool-policy/preset/open_bug_bounty",
        headers=_hdrs(token),
    )
    assert r.status_code == 200
    assert r.json()["cleared"] >= 1
    snap = client.get(f"/engagements/{eng_id}/tool-policy",
                      headers=_hdrs(token)).json()
    assert snap["rows"] == []


@pytest.mark.integration
def test_apply_unknown_preset_400(api) -> None:
    client, token, eng_id = api
    r = client.post(
        f"/engagements/{eng_id}/tool-policy/preset/totally-fake",
        headers=_hdrs(token),
    )
    assert r.status_code == 400


# ──────────────────────────── DELETE ────────────────────────────


@pytest.mark.integration
def test_delete_clears_all_rows(api) -> None:
    client, token, eng_id = api
    client.put(
        f"/engagements/{eng_id}/tool-policy/capability/wrk",
        json={"allowed": False},
        headers=_hdrs(token),
    )
    r = client.delete(f"/engagements/{eng_id}/tool-policy",
                      headers=_hdrs(token))
    assert r.status_code == 204
    snap = client.get(f"/engagements/{eng_id}/tool-policy",
                      headers=_hdrs(token)).json()
    assert snap["rows"] == []


# ──────────────────────────── Enforcement at /steps/run ────────────────────────────


@pytest.mark.integration
def test_steps_run_blocked_by_step_policy(api) -> None:
    client, token, eng_id = api
    client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.stage1.crtsh",
        json={"allowed": False, "note": "reserved for live test"},
        headers=_hdrs(token),
    )
    r = client.post(
        "/steps/run",
        json={"engagement_id": eng_id, "step_id": "bb.stage1.crtsh"},
        headers=_hdrs(token),
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["error"] == "blocked_by_tool_policy"
    assert detail["target_kind"] == "step"
    assert detail["target_value"] == "bb.stage1.crtsh"


@pytest.mark.integration
def test_steps_run_blocked_by_capability_cascade(api) -> None:
    client, token, eng_id = api
    # Block the wrk capability
    client.put(
        f"/engagements/{eng_id}/tool-policy/capability/wrk",
        json={"allowed": False, "note": "no DoS"},
        headers=_hdrs(token),
    )
    # Now any step that requires `wrk` should 403
    r = client.post(
        "/steps/run",
        json={"engagement_id": eng_id,
              "step_id": "wp_stress.phase2.escalating"},
        headers=_hdrs(token),
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["target_kind"] == "capability"
    assert detail["target_value"] == "wrk"


@pytest.mark.integration
def test_steps_run_unaffected_when_allowed(api) -> None:
    client, token, eng_id = api
    # Flip the toggle but back to allowed
    client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.stage1.crtsh",
        json={"allowed": True},
        headers=_hdrs(token),
    )
    r = client.post(
        "/steps/run",
        json={"engagement_id": eng_id, "step_id": "bb.stage1.crtsh"},
        headers=_hdrs(token),
    )
    assert r.status_code == 201
    assert r.json()["step_id"] == "bb.stage1.crtsh"


# ──────────────────────────── Defensive filter at /jobs/next ────────────────────────────


@pytest.mark.integration
def test_jobs_next_skips_steps_blocked_after_queue(api) -> None:
    """Queue a step → flip the policy to block it → worker should NOT
    receive it on the next claim attempt."""
    client, token, eng_id = api
    # Queue while still allowed
    r = client.post(
        "/steps/run",
        json={"engagement_id": eng_id, "step_id": "bb.stage1.crtsh"},
        headers=_hdrs(token),
    )
    assert r.status_code == 201
    # Register a worker that could otherwise claim it
    client.post("/workers/register",
                json={"id": "w1", "hostname": "x", "os": "linux",
                      "capabilities": ["network", "dig", "openssl"]},
                headers=_hdrs(token)).raise_for_status()
    # NOW block it
    client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.stage1.crtsh",
        json={"allowed": False, "note": "operator paused"},
        headers=_hdrs(token),
    )
    # Worker poll returns null (job exists but is filtered out)
    r = client.get("/jobs/next",
                   params={"worker_id": "w1", "runtime": "linux",
                           "capabilities": ["network", "dig", "openssl"]},
                   headers=_hdrs(token))
    assert r.json() is None
    # Re-allow → worker now claims it
    client.put(
        f"/engagements/{eng_id}/tool-policy/step/bb.stage1.crtsh",
        json={"allowed": True},
        headers=_hdrs(token),
    )
    r = client.get("/jobs/next",
                   params={"worker_id": "w1", "runtime": "linux",
                           "capabilities": ["network", "dig", "openssl"]},
                   headers=_hdrs(token))
    body = r.json()
    assert body is not None
    assert body["step_id"] == "bb.stage1.crtsh"
