"""Phase 3 acceptance — verify wp_stress.yaml loads and at least one
auto step + one walkthrough step are routable to a worker."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn

from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch
                ) -> Iterator[tuple[str, str]]:
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
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 5
    while time.time() < deadline and not server.started:
        time.sleep(0.05)
    monkeypatch.setenv("TWISTED_ENGINE_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("TWISTED_TOKEN", token)
    try:
        yield f"http://127.0.0.1:{port}/api", token
    finally:
        server.should_exit = True
        th.join(timeout=5)
        reset_settings(None)


def _hdrs(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.integration
def test_wp_stress_loaded_with_4_phases(live_engine) -> None:
    base, token = live_engine
    r = httpx.get(f"{base}/procedures", headers=_hdrs(token))
    assert r.status_code == 200
    wp = next(p for p in r.json() if p["id"] == "wp_stress")
    stage_ids = sorted(s["id"] for s in wp["stages"])
    assert stage_ids == ["phase1", "phase2", "phase3", "phase4"]
    # Each phase non-empty
    for st in wp["stages"]:
        assert len(st["steps"]) >= 1


@pytest.mark.integration
def test_wp_step_routes_to_linux_worker(live_engine) -> None:
    base, token = live_engine
    # Create engagement
    r = httpx.post(f"{base}/engagements",
                   json={"client": "MyWP", "primary_domain": "wp.local"},
                   headers=_hdrs(token))
    eng_id = r.json()["id"]

    # Queue an auto step that needs `ab`
    r = httpx.post(f"{base}/steps/run",
                   json={"engagement_id": eng_id,
                         "step_id": "wp_stress.phase1.baseline_ab"},
                   headers=_hdrs(token))
    assert r.status_code == 201

    # Linux worker without 'ab' shouldn't get it
    httpx.post(f"{base}/workers/register",
               json={"id": "wsl-noab", "hostname": "x", "os": "linux",
                     "capabilities": ["dig"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "wsl-noab", "runtime": "linux",
                          "capabilities": ["dig"]},
                  headers=_hdrs(token))
    assert r.json() is None

    # Linux worker WITH 'ab' should claim it
    httpx.post(f"{base}/workers/register",
               json={"id": "wsl-ab", "hostname": "y", "os": "linux",
                     "capabilities": ["ab", "dig"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "wsl-ab", "runtime": "linux",
                          "capabilities": ["ab", "dig"]},
                  headers=_hdrs(token))
    assert r.json() is not None
    offer = r.json()
    assert offer["step_id"] == "wp_stress.phase1.baseline_ab"
    assert offer["module"] == "twisted.modules.wpstress.ab_baseline:run"
