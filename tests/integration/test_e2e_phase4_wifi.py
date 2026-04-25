"""Phase 4 acceptance — verify wifi_pentest.yaml loads and routes."""

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
    while not server.started:
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
def test_wifi_pentest_loaded_with_5_phases(live_engine) -> None:
    base, token = live_engine
    r = httpx.get(f"{base}/procedures", headers=_hdrs(token))
    wifi = next(p for p in r.json() if p["id"] == "wifi")
    stage_ids = sorted(s["id"] for s in wifi["stages"])
    assert stage_ids == ["phase0", "phase1", "phase2", "phase3", "phase4"]


@pytest.mark.integration
def test_monitor_mode_step_requires_capability(live_engine) -> None:
    base, token = live_engine
    r = httpx.post(f"{base}/engagements",
                   json={"client": "WifiTest", "primary_domain": "lab.local"},
                   headers=_hdrs(token))
    eng_id = r.json()["id"]
    r = httpx.post(f"{base}/steps/run",
                   json={"engagement_id": eng_id,
                         "step_id": "wifi.phase1.monitor_mode"},
                   headers=_hdrs(token))
    assert r.status_code == 201

    # Linux worker without 'monitor-mode' capability is correctly excluded
    httpx.post(f"{base}/workers/register",
               json={"id": "no-monitor", "hostname": "x", "os": "linux",
                     "capabilities": ["airmon-ng", "iw"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "no-monitor", "runtime": "linux",
                          "capabilities": ["airmon-ng", "iw"]},
                  headers=_hdrs(token))
    assert r.json() is None

    # Linux worker WITH 'monitor-mode' claims it
    httpx.post(f"{base}/workers/register",
               json={"id": "kali-1", "hostname": "y", "os": "linux",
                     "capabilities": ["airmon-ng", "iw", "monitor-mode"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "kali-1", "runtime": "linux",
                          "capabilities": ["airmon-ng", "iw", "monitor-mode"]},
                  headers=_hdrs(token))
    assert r.json() is not None
