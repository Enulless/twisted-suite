"""Worker daemon + dispatch tests.

The fake EngineClient replaces the HTTP layer so these tests are fast
and deterministic. A separate test exercises the dispatch path against a
real in-process engine via TestClient.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from twisted.client.api import EngineClient
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token
from twisted.modules.base import (
    AssetUpdate,
    EvidenceRef,
    FindingDraft,
    ModuleContext,
    ModuleResult,
)
from twisted.worker.daemon import WorkerConfig, WorkerDaemon
from twisted.worker.dispatch import dispatch, resolve_callable, serialise_result

# ──────────────────────────── Dispatch unit ────────────────────────────


def _stub_module(ctx: ModuleContext) -> ModuleResult:
    artifact = ctx.work_dir / "stub.txt"
    artifact.write_text("stub")
    return ModuleResult(
        success=True,
        summary="stub ran",
        artifacts=[artifact],
        assets=[AssetUpdate(host="api.acme.example", source="stub")],
        findings=[FindingDraft(title="fake finding", severity="low")],
        evidence=[EvidenceRef(path=str(artifact), kind="command_output", host="wsl")],
    )


def _exploding_module(ctx: ModuleContext) -> ModuleResult:
    raise RuntimeError("boom")


def _bad_return_module(ctx: ModuleContext) -> Any:
    return "not a ModuleResult"


# Expose at module scope so resolve_callable() can find them
__all__ = ["_stub_module", "_exploding_module", "_bad_return_module"]


class TestDispatchResolution:
    def test_resolve_callable_happy(self) -> None:
        fn = resolve_callable("twisted.modules.recon.crtsh:run")
        assert callable(fn)

    def test_resolve_callable_bad_format(self) -> None:
        with pytest.raises(ValueError):
            resolve_callable("no-colon-here")

    def test_resolve_callable_missing_attr(self) -> None:
        with pytest.raises(AttributeError):
            resolve_callable("twisted.modules.recon.crtsh:nope")


class TestDispatchExecution:
    def test_dispatch_happy_path(self, tmp_path: Path) -> None:
        offer = {
            "job_id": 1, "step_run_id": 1, "engagement_id": 7,
            "procedure": "bb", "stage": "stage1",
            "step_id": "bb.stage1.test",
            "module": "tests.integration.test_worker:_stub_module",
            "params": {},
            "work_dir": str(tmp_path),
        }
        result = dispatch(offer)
        assert result.success
        assert result.summary == "stub ran"
        assert result.assets[0].host == "api.acme.example"

    def test_dispatch_module_exception_returns_failure(self, tmp_path: Path) -> None:
        offer = {
            "job_id": 1, "engagement_id": 1, "procedure": "bb",
            "stage": "stage1", "step_id": "x",
            "module": "tests.integration.test_worker:_exploding_module",
            "params": {}, "work_dir": str(tmp_path),
        }
        result = dispatch(offer)
        assert not result.success
        assert "boom" in (result.error or "")

    def test_dispatch_bad_return_type(self, tmp_path: Path) -> None:
        offer = {
            "job_id": 1, "engagement_id": 1, "procedure": "bb",
            "stage": "stage1", "step_id": "x",
            "module": "tests.integration.test_worker:_bad_return_module",
            "params": {}, "work_dir": str(tmp_path),
        }
        result = dispatch(offer)
        assert not result.success
        assert "expected ModuleResult" in (result.error or "")

    def test_dispatch_walkthrough_with_no_module(self, tmp_path: Path) -> None:
        offer = {"job_id": 1, "engagement_id": 1, "procedure": "bb",
                 "stage": "stage4", "step_id": "x", "module": None,
                 "params": {}, "work_dir": str(tmp_path)}
        result = dispatch(offer)
        assert not result.success
        assert "walkthrough" in (result.error or "").lower()

    def test_serialise_fills_sha_and_size(self, tmp_path: Path) -> None:
        f = tmp_path / "evidence.txt"
        f.write_text("hello")
        result = ModuleResult(
            success=True,
            evidence=[EvidenceRef(path=str(f), kind="command_output", host="wsl")],
        )
        payload = serialise_result(result)
        assert payload["evidence"][0]["sha256"] is not None
        assert payload["evidence"][0]["size_bytes"] == 5


# ──────────────────────────── Daemon (fake engine) ────────────────────────────


class FakeClient:
    def __init__(self, *, offers: list[dict | None]):
        self.offers = list(offers)
        self.registered: dict | None = None
        self.heartbeats: list[str] = []
        self.results: list[tuple[int, dict]] = []
        self.starts: list[int] = []

    def register_worker(self, payload: dict) -> dict:
        self.registered = payload
        return {**payload, "status": "online"}

    def heartbeat(self, worker_id: str) -> dict:
        self.heartbeats.append(worker_id)
        return {"id": worker_id, "status": "online"}

    def claim_next(self, worker_id: str, runtime: str, capabilities: list[str]) -> dict | None:
        if not self.offers:
            return None
        return self.offers.pop(0)

    def mark_running(self, job_id: int) -> dict:
        self.starts.append(job_id)
        return {"id": job_id, "state": "running"}

    def submit_result(self, job_id: int, payload: dict) -> dict:
        self.results.append((job_id, payload))
        return {"step_run_id": job_id, "status": "done"}

    def close(self) -> None:
        pass


class TestDaemon:
    def _config(self) -> WorkerConfig:
        return WorkerConfig(
            runtime="linux", worker_id="t-worker-1", hostname="t",
            capabilities=["network"], poll_interval=0.0, heartbeat_interval=0.0,
            settings=Settings(),
        )

    def test_processes_offered_jobs(self, tmp_path: Path) -> None:
        client = FakeClient(offers=[
            {"job_id": 1, "step_run_id": 1, "engagement_id": 7,
             "procedure": "bb", "stage": "stage1", "step_id": "bb.stage1.test",
             "module": "tests.integration.test_worker:_stub_module",
             "params": {}, "work_dir": str(tmp_path)},
            None,
            None,
        ])
        d = WorkerDaemon(self._config(), client_factory=lambda: client,
                         sleep=lambda _t: None)
        processed = d.run(max_iterations=4)
        assert processed == 1
        assert client.registered is not None
        assert client.results
        job_id, payload = client.results[0]
        assert job_id == 1
        assert payload["success"] is True

    def test_heartbeat_when_idle(self, tmp_path: Path) -> None:
        client = FakeClient(offers=[None, None, None])
        d = WorkerDaemon(self._config(), client_factory=lambda: client,
                         sleep=lambda _t: None)
        d.run(max_iterations=3)
        assert client.heartbeats  # at least one heartbeat


# ──────────────────────────── Daemon -> real engine ────────────────────────────


@pytest.fixture
def engine_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, str, Settings]]:
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{tmp_path}/data/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    app = create_app(settings=s)
    token = ensure_token(s)
    client = TestClient(app)
    try:
        yield client, token, s
    finally:
        reset_settings(None)


class _TestClientEngine(EngineClient):
    """An EngineClient that talks to a FastAPI TestClient instead of httpx."""

    def __init__(self, test_client: TestClient, token: str):
        # Don't call super().__init__ (it would open a real httpx client).
        self._tc = test_client
        self._token = token

    def _hdrs(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    def register_worker(self, payload: dict) -> dict:
        r = self._tc.post("/workers/register", json=payload, headers=self._hdrs())
        r.raise_for_status()
        return r.json()

    def heartbeat(self, worker_id: str) -> dict:
        r = self._tc.post(f"/workers/{worker_id}/heartbeat", headers=self._hdrs())
        r.raise_for_status()
        return r.json()

    def claim_next(self, worker_id: str, runtime: str, capabilities: list[str]) -> dict | None:
        r = self._tc.get("/jobs/next",
                         params={"worker_id": worker_id, "runtime": runtime,
                                 "capabilities": capabilities},
                         headers=self._hdrs())
        r.raise_for_status()
        return r.json()

    def mark_running(self, job_id: int) -> dict:
        r = self._tc.post(f"/jobs/{job_id}/start", headers=self._hdrs())
        r.raise_for_status()
        return r.json()

    def submit_result(self, job_id: int, payload: dict) -> dict:
        r = self._tc.post(f"/jobs/{job_id}/result", json=payload, headers=self._hdrs())
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        pass


class TestDaemonAgainstRealEngine:
    def test_full_round_trip(self, engine_app, tmp_path: Path) -> None:
        client, token, settings = engine_app
        # Engagement
        r = client.post("/engagements",
                        json={"client": "ACME", "primary_domain": "acme.example",
                              "scope": [{"kind": "wildcard", "pattern": "acme.example"}]},
                        headers={"Authorization": f"Bearer {token}"})
        eng_id = r.json()["id"]

        # Queue an automatable step
        r = client.post("/steps/run",
                        json={"engagement_id": eng_id, "step_id": "bb.stage1.crtsh"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 201, r.text

        # Mock crt.sh inside the worker so we don't hit the real internet.
        from twisted.modules.recon import crtsh as crtsh_mod
        with patch.object(crtsh_mod, "_query_crtsh",
                           return_value=[{"name_value": "api.acme.example\nstaging.acme.example"}]):
            cfg = WorkerConfig(
                runtime="linux", worker_id="t-w", hostname="t",
                capabilities=["network"], poll_interval=0.0,
                heartbeat_interval=0.0, settings=settings,
            )
            daemon = WorkerDaemon(
                cfg, client_factory=lambda: _TestClientEngine(client, token),
                sleep=lambda _t: None,
            )
            processed = daemon.run(max_iterations=3)
        assert processed == 1

        # Confirm assets landed
        r = client.get(f"/engagements/{eng_id}/assets",
                       headers={"Authorization": f"Bearer {token}"})
        hosts = sorted(a["host"] for a in r.json())
        assert "api.acme.example" in hosts
        assert "staging.acme.example" in hosts
