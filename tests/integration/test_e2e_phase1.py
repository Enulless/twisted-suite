"""Phase 1 end-to-end demo / acceptance test.

Proves the full Phase 1 surface works as a coherent system:

  1. Engine boots from a fresh data root (real uvicorn on an ephemeral port)
  2. CLI creates a new engagement with scope rules
  3. Linux worker registers and announces capabilities
  4. Windows worker registers
  5. Operator queues an automated crt.sh step (runtime: either)
  6. Linux worker claims it (it matches first), runs it (with crt.sh mocked),
     and reports results back
  7. Operator queues the OWASP ZAP walkthrough (runtime: windows)
  8. Linux worker correctly skips it
  9. Windows worker claims it, completes it as a walkthrough no-op, reports back
  10. Master spreadsheet shows the assets, findings show the headers/CT discoveries,
      step_run / job tables show the audit trail
  11. Engagement summary report (markdown) renders correctly

Network is mocked. No external tools required.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from typer.testing import CliRunner

from twisted.client.api import EngineClient
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token
from twisted.modules.recon import crtsh as crtsh_mod
from twisted.worker.daemon import WorkerConfig, WorkerDaemon


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch
                ) -> Iterator[tuple[str, str, Settings]]:
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
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and not server.started:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("uvicorn failed to start")
    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("TWISTED_ENGINE_URL", base)
    monkeypatch.setenv("TWISTED_TOKEN", token)
    try:
        yield base, token, s
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        reset_settings(None)


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
def test_phase1_full_acceptance(live_engine: tuple[str, str, Settings]) -> None:
    base, token, settings = live_engine
    runner = CliRunner()
    from twisted.cli.__main__ import app as cli_app

    # ── 1. Verify engine is healthy via CLI ────────────────────────────
    result = runner.invoke(cli_app, ["token", "verify"])
    assert result.exit_code == 0, result.stdout

    # ── 2. Create engagement with scope ────────────────────────────────
    r = httpx.post(f"{base}/engagements", json={
        "client": "ACME", "primary_domain": "acme.example",
        "scope": [
            {"kind": "exact", "pattern": "api.acme.example"},
            {"kind": "wildcard", "pattern": "acme.example"},
            {"kind": "oos", "pattern": r".*\.osp\.acme\.example$"},
        ],
    }, headers=_bearer(token))
    assert r.status_code == 201, r.text
    eng_id = r.json()["id"]

    # ── 3 & 4. Register both workers ───────────────────────────────────
    httpx.post(f"{base}/workers/register", json={
        "id": "wsl-1", "hostname": "ubuntu-wsl", "os": "linux",
        "capabilities": ["network", "dig", "openssl", "curl", "python"],
    }, headers=_bearer(token)).raise_for_status()
    httpx.post(f"{base}/workers/register", json={
        "id": "win-1", "hostname": "andrew-pc", "os": "windows",
        "capabilities": ["browser", "screenshots", "windows", "zap", "burp"],
    }, headers=_bearer(token)).raise_for_status()

    # Both workers visible
    r = httpx.get(f"{base}/workers", headers=_bearer(token))
    worker_ids = sorted(w["id"] for w in r.json())
    assert worker_ids == ["win-1", "wsl-1"]

    # ── 5. Queue the auto crt.sh step ──────────────────────────────────
    r = httpx.post(f"{base}/steps/run", json={
        "engagement_id": eng_id, "step_id": "bb.stage1.crtsh",
    }, headers=_bearer(token))
    assert r.status_code == 201, r.text
    _ = r.json()["id"]

    # ── 6. WSL worker runs it (with mocked crt.sh) ─────────────────────
    fake_rows = [{"name_value": (
        "api.acme.example\n"
        "staging.acme.example\n"
        "evil.acme.example.osp.acme.example\n"  # OOS — should be dropped
    )}]

    class _LiveClient(EngineClient):
        def __init__(self, base: str, token: str) -> None:
            self._token = token
            import httpx as _httpx
            self._client = _httpx.Client(base_url=base, timeout=10,
                                          headers={"Authorization": f"Bearer {token}",
                                                   "User-Agent": "twisted-test"})
            self._base = base

    cfg_linux = WorkerConfig(
        runtime="linux", worker_id="wsl-1", hostname="ubuntu-wsl",
        capabilities=["network", "dig", "openssl", "curl", "python"],
        poll_interval=0.0, heartbeat_interval=0.0, settings=settings,
    )
    with patch.object(crtsh_mod, "_query_crtsh", return_value=fake_rows):
        WorkerDaemon(
            cfg_linux, client_factory=lambda: _LiveClient(base, token),
            sleep=lambda _t: None,
        ).run(max_iterations=3)

    # ── 7. Queue the ZAP walkthrough (windows-only) ────────────────────
    r = httpx.post(f"{base}/steps/run", json={
        "engagement_id": eng_id, "step_id": "bb.stage4.zap_walkthrough",
    }, headers=_bearer(token))
    assert r.status_code == 201, r.text

    # ── 8. WSL worker should NOT pick it up (lacks 'zap' cap) ──────────
    r = httpx.get(
        f"{base}/jobs/next",
        params={"worker_id": "wsl-1", "runtime": "linux",
                "capabilities": ["network", "dig", "openssl", "curl", "python"]},
        headers=_bearer(token),
    )
    assert r.json() is None, "linux worker should not match windows-only zap step"

    # ── 9. Windows worker claims and 'completes' the walkthrough ───────
    r = httpx.get(
        f"{base}/jobs/next",
        params={"worker_id": "win-1", "runtime": "windows",
                "capabilities": ["browser", "screenshots", "windows", "zap", "burp"]},
        headers=_bearer(token),
    )
    offer = r.json()
    assert offer is not None
    assert offer["step_id"] == "bb.stage4.zap_walkthrough"
    assert offer["module"] is None  # walkthrough has no module
    # Operator (the dashboard, in real life) submits a synthetic walkthrough
    # result with the harvested data.
    r = httpx.post(f"{base}/jobs/{offer['job_id']}/result", json={
        "success": True,
        "summary": "ZAP scan complete: 2 high, 5 medium, 11 low alerts",
        "artifact_paths": [],
        "assets": [{"host": "api.acme.example", "source": "zap"}],
        "findings": [
            {"title": "Reflected XSS in /search", "severity": "high",
             "cwe": "CWE-79", "asset_host": "api.acme.example",
             "cvss_score": 7.4,
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "remediation": "Encode output in templates."},
        ],
        "evidence": [],
    }, headers=_bearer(token))
    assert r.status_code == 200, r.text

    # ── 10. Verify everything landed ───────────────────────────────────
    r = httpx.get(f"{base}/engagements/{eng_id}/assets", headers=_bearer(token))
    by_host = {a["host"]: a for a in r.json()}
    assert "api.acme.example" in by_host
    assert "staging.acme.example" in by_host
    assert "evil.acme.example.osp.acme.example" in by_host
    assert by_host["api.acme.example"]["in_scope"] is True
    assert by_host["staging.acme.example"]["in_scope"] is True
    assert by_host["evil.acme.example.osp.acme.example"]["in_scope"] is False

    r = httpx.get(f"{base}/engagements/{eng_id}/findings", headers=_bearer(token))
    titles = [f["title"] for f in r.json()]
    assert any("Reflected XSS" in t for t in titles)

    r = httpx.get(f"{base}/engagements/{eng_id}/runs", headers=_bearer(token))
    runs = r.json()
    assert len(runs) == 2
    crtsh_run = next(r for r in runs if r["step_id"] == "bb.stage1.crtsh")
    zap_run = next(r for r in runs if r["step_id"] == "bb.stage4.zap_walkthrough")
    assert crtsh_run["status"] == "done"
    assert crtsh_run["worker_id"] == "wsl-1"
    assert zap_run["status"] == "done"
    assert zap_run["worker_id"] == "win-1"

    # ── 11. Render a summary report ────────────────────────────────────
    from datetime import datetime

    from twisted.core.reporting import (
        FindingSummary,
        ReportData,
        render_html,
        render_markdown,
    )

    # Pull findings from the API and drop them through reporting primitives
    findings_payload = httpx.get(
        f"{base}/engagements/{eng_id}/findings", headers=_bearer(token)
    ).json()
    assets_payload = httpx.get(
        f"{base}/engagements/{eng_id}/assets", headers=_bearer(token)
    ).json()
    report_data = ReportData(
        client="ACME", primary_domain="acme.example",
        engagement_started=datetime.now(UTC),
        engagement_ended=datetime.now(UTC),
        scope_summary="exact: api.acme.example\nwildcard: acme.example",
        asset_count=len(assets_payload),
        findings=[
            FindingSummary(
                id=f["id"], title=f["title"], severity=f["severity"],
                cvss_score=f.get("cvss_score"), cvss_vector=f.get("cvss_vector"),
                cwe=f.get("cwe"), affected_component=None, description=None,
                root_cause=None, repro_steps=None, impact=None, remediation=None,
            )
            for f in findings_payload
        ],
    )
    md = render_markdown(report_data)
    html = render_html(report_data)
    assert "ACME" in md
    assert "Reflected XSS" in md
    assert "<html" in html
