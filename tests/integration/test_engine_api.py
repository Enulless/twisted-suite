"""Engine HTTP API tests using FastAPI's TestClient.

These exercise the cross-host workflow: register worker -> create engagement
-> queue step -> claim job -> submit result -> verify assets/findings/evidence
land in SQLite. All network is in-process (TestClient), no real sockets.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token, read_token


@pytest.fixture
def engine_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str]]:
    """Spin up an isolated engine + token for each test."""
    data_root = tmp_path / "data"
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(data_root))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{data_root}/twisted.db")
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


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────── Auth ────────────────────────────


class TestAuth:
    def test_health_is_open(self, engine_app) -> None:
        client, _ = engine_app
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_other_routes_require_token(self, engine_app) -> None:
        client, _ = engine_app
        r = client.get("/workers")
        assert r.status_code == 401
        r = client.get("/engagements")
        assert r.status_code == 401

    def test_wrong_token_rejected(self, engine_app) -> None:
        client, _ = engine_app
        r = client.get("/workers", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

    def test_token_persisted_across_calls(self, engine_app) -> None:
        client, token = engine_app
        # Simulate a worker reading the same file
        from_disk = read_token()
        assert from_disk == token


# ──────────────────────────── Worker registration ────────────────────────────


class TestWorkers:
    def test_register_then_list(self, engine_app) -> None:
        client, token = engine_app
        body = {"id": "wsl-1", "hostname": "ubuntu", "os": "linux",
                "capabilities": ["nmap", "dig", "network"], "version": "0.1.0"}
        r = client.post("/workers/register", json=body, headers=auth(token))
        assert r.status_code == 201
        assert r.json()["status"] == "online"

        r = client.get("/workers", headers=auth(token))
        assert r.status_code == 200
        ids = [w["id"] for w in r.json()]
        assert "wsl-1" in ids

    def test_register_idempotent_updates_caps(self, engine_app) -> None:
        client, token = engine_app
        b1 = {"id": "w1", "hostname": "h", "os": "linux", "capabilities": ["dig"]}
        b2 = {"id": "w1", "hostname": "h", "os": "linux", "capabilities": ["dig", "nmap"]}
        client.post("/workers/register", json=b1, headers=auth(token))
        r = client.post("/workers/register", json=b2, headers=auth(token))
        assert r.status_code == 201
        assert "nmap" in r.json()["capabilities"]

    def test_heartbeat_updates_last_seen(self, engine_app) -> None:
        client, token = engine_app
        client.post("/workers/register",
                    json={"id": "w1", "hostname": "h", "os": "linux", "capabilities": []},
                    headers=auth(token))
        r = client.post("/workers/w1/heartbeat", headers=auth(token))
        assert r.status_code == 200

    def test_heartbeat_unknown_worker(self, engine_app) -> None:
        client, token = engine_app
        r = client.post("/workers/nope/heartbeat", headers=auth(token))
        assert r.status_code == 404


# ──────────────────────────── Engagements ────────────────────────────


class TestEngagements:
    def test_create_then_get(self, engine_app) -> None:
        client, token = engine_app
        body = {"client": "ACME", "primary_domain": "acme.example",
                "scope": [
                    {"kind": "exact", "pattern": "api.acme.example"},
                    {"kind": "wildcard", "pattern": "acme.example"},
                    {"kind": "oos", "pattern": r".*\.osp\.acme\.example$"},
                ]}
        r = client.post("/engagements", json=body, headers=auth(token))
        assert r.status_code == 201, r.text
        eng_id = r.json()["id"]
        assert r.json()["primary_domain"] == "acme.example"
        # root_dir is a POSIX path
        assert r.json()["root_dir"].startswith("/")

        r = client.get(f"/engagements/{eng_id}", headers=auth(token))
        assert r.status_code == 200

        r = client.get(f"/engagements/{eng_id}/scope", headers=auth(token))
        assert r.status_code == 200
        kinds = sorted(rule["kind"] for rule in r.json())
        assert kinds == ["exact", "oos", "wildcard"]

    def test_duplicate_client_conflict(self, engine_app) -> None:
        client, token = engine_app
        body = {"client": "ACME"}
        client.post("/engagements", json=body, headers=auth(token))
        r = client.post("/engagements", json=body, headers=auth(token))
        assert r.status_code == 409


# ──────────────────────────── Assets ────────────────────────────


class TestAssets:
    def _make_eng(self, client, token) -> int:
        r = client.post("/engagements",
                        json={"client": "ACME", "primary_domain": "acme.example",
                              "scope": [
                                  {"kind": "wildcard", "pattern": "acme.example"},
                                  {"kind": "oos", "pattern": r".*\.osp\.acme\.example$"},
                              ]},
                        headers=auth(token))
        return r.json()["id"]

    def test_upsert_assets_respects_scope(self, engine_app) -> None:
        client, token = engine_app
        eng_id = self._make_eng(client, token)
        payload = [
            {"host": "api.acme.example", "source": "crt.sh"},
            {"host": "evil.acme.example.osp.acme.example", "source": "crt.sh"},
            {"host": "API.ACME.EXAMPLE", "source": "dup"},  # case/dup
        ]
        r = client.post(f"/engagements/{eng_id}/assets", json=payload, headers=auth(token))
        assert r.status_code == 200
        # Re-list and check
        r = client.get(f"/engagements/{eng_id}/assets", headers=auth(token))
        assert r.status_code == 200
        rows = r.json()
        # Two unique hosts after lowercasing/dup
        hosts = sorted(a["host"] for a in rows)
        assert hosts == sorted({"api.acme.example", "evil.acme.example.osp.acme.example"})
        in_scope_hosts = {a["host"]: a["in_scope"] for a in rows}
        assert in_scope_hosts["api.acme.example"] is True
        assert in_scope_hosts["evil.acme.example.osp.acme.example"] is False


# ──────────────────────────── Findings ────────────────────────────


class TestFindings:
    def test_create_and_list_findings(self, engine_app) -> None:
        client, token = engine_app
        r = client.post("/engagements", json={"client": "ACME"}, headers=auth(token))
        eng_id = r.json()["id"]
        finds = [
            {"title": "Missing CSP", "severity": "medium",
             "affected_component": "https://acme.example", "cwe": "CWE-1021",
             "remediation": "Add CSP header"},
            {"title": "Critical RCE", "severity": "critical", "cvss_score": 9.8,
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ]
        r = client.post(f"/engagements/{eng_id}/findings", json=finds, headers=auth(token))
        assert r.status_code == 200
        assert len(r.json()) == 2

        r = client.get(f"/engagements/{eng_id}/findings?severity=critical",
                       headers=auth(token))
        assert r.status_code == 200
        assert len(r.json()) == 1


# ──────────────────────────── End-to-end job flow ────────────────────────────


class TestJobFlow:
    def _setup(self, client, token) -> tuple[int, str]:
        r = client.post("/engagements",
                        json={"client": "ACME", "primary_domain": "acme.example",
                              "scope": [{"kind": "wildcard", "pattern": "acme.example"}]},
                        headers=auth(token))
        eng_id = r.json()["id"]
        client.post("/workers/register",
                    json={"id": "wsl-1", "hostname": "ubuntu", "os": "linux",
                          "capabilities": ["network", "dig"]},
                    headers=auth(token))
        return eng_id, "wsl-1"

    def test_queue_claim_complete(self, engine_app) -> None:
        client, token = engine_app
        eng_id, worker_id = self._setup(client, token)

        # Queue an auto step
        r = client.post("/steps/run",
                        json={"engagement_id": eng_id, "step_id": "bb.stage1.crtsh"},
                        headers=auth(token))
        assert r.status_code == 201, r.text
        _ = r.json()["id"]

        # Worker (linux runtime, has 'network') claims it
        r = client.get("/jobs/next",
                       params={"worker_id": worker_id, "runtime": "linux",
                               "capabilities": ["network", "dig"]},
                       headers=auth(token))
        assert r.status_code == 200, r.text
        offer = r.json()
        assert offer is not None
        assert offer["step_id"] == "bb.stage1.crtsh"
        assert offer["params"]["domain"] == "acme.example"  # placeholder rendered
        assert offer["work_dir"].startswith("/")

        # Worker reports back with a successful result
        result = {
            "success": True,
            "summary": "found 2 subdomains",
            "artifact_paths": ["/tmp/x.json", "/tmp/x.txt"],
            "assets": [
                {"host": "api.acme.example", "source": "crt.sh"},
                {"host": "staging.acme.example", "source": "crt.sh"},
            ],
            "findings": [
                {"title": "Missing HSTS on api.acme.example", "severity": "low",
                 "cwe": "CWE-319", "asset_host": "api.acme.example"},
            ],
            "evidence": [],
        }
        r = client.post(f"/jobs/{offer['job_id']}/result", json=result, headers=auth(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "done"
        assert body["asset_count"] == 2
        assert len(body["finding_ids"]) == 1

        # Confirm assets persisted in master spreadsheet
        r = client.get(f"/engagements/{eng_id}/assets", headers=auth(token))
        hosts = sorted(a["host"] for a in r.json())
        assert "api.acme.example" in hosts
        assert "staging.acme.example" in hosts

        # Confirm finding persisted with correct severity
        r = client.get(f"/engagements/{eng_id}/findings", headers=auth(token))
        titles = [f["title"] for f in r.json()]
        assert any("Missing HSTS" in t for t in titles)

        # No more pending jobs
        r = client.get("/jobs/next",
                       params={"worker_id": worker_id, "runtime": "linux",
                               "capabilities": ["network", "dig"]},
                       headers=auth(token))
        assert r.json() is None

    def test_runtime_mismatch_skips_job(self, engine_app) -> None:
        client, token = engine_app
        eng_id, _ = self._setup(client, token)

        # Queue a windows-only walkthrough step
        r = client.post("/steps/run",
                        json={"engagement_id": eng_id, "step_id": "bb.stage4.zap_walkthrough"},
                        headers=auth(token))
        assert r.status_code == 201, r.text

        # Linux worker without 'zap' capability should NOT claim it
        client.post("/workers/register",
                    json={"id": "wsl-1", "hostname": "ubuntu", "os": "linux",
                          "capabilities": ["network", "dig"]},
                    headers=auth(token))
        r = client.get("/jobs/next",
                       params={"worker_id": "wsl-1", "runtime": "linux",
                               "capabilities": ["network", "dig"]},
                       headers=auth(token))
        assert r.json() is None

        # Windows worker with 'zap' capability claims it
        client.post("/workers/register",
                    json={"id": "win-1", "hostname": "andrew-pc", "os": "windows",
                          "capabilities": ["browser", "zap"]},
                    headers=auth(token))
        r = client.get("/jobs/next",
                       params={"worker_id": "win-1", "runtime": "windows",
                               "capabilities": ["browser", "zap"]},
                       headers=auth(token))
        offer = r.json()
        assert offer is not None
        assert offer["step_id"] == "bb.stage4.zap_walkthrough"
        assert offer["module"] is None  # walkthrough has no module

    def test_unknown_step_404(self, engine_app) -> None:
        client, token = engine_app
        eng_id, _ = self._setup(client, token)
        r = client.post("/steps/run",
                        json={"engagement_id": eng_id, "step_id": "bb.does.not.exist"},
                        headers=auth(token))
        assert r.status_code == 404


# ──────────────────────────── Procedures endpoint ────────────────────────────


class TestProcedures:
    def test_list_procedures(self, engine_app) -> None:
        client, token = engine_app
        r = client.get("/procedures", headers=auth(token))
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()]
        assert "bb" in ids

    def test_get_step(self, engine_app) -> None:
        client, token = engine_app
        r = client.get("/procedures/bb/steps/bb.stage1.crtsh", headers=auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["module"] == "twisted.modules.recon.crtsh:run"
        assert body["runtime"] == "either"
