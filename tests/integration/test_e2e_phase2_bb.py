"""Phase 2 acceptance — drive the full Bug Bounty procedure end-to-end.

Mocks crt.sh, dig, NVD, and the worker tool wrappers; everything else
runs through real HTTP against a real uvicorn-backed engine. Verifies:

- All 5 stages are loadable from bug_bounty.yaml
- Procedure metadata is exposed via /procedures
- Engagement creation + scope rules
- Stage 1 crt.sh + dns + email_security run and populate assets/findings
- Stage 3 risk_scoring runs against the engine and posts back per-asset
  totals + breakdown rows
- Stage 5 report build pulls the engagement and renders MD + HTML
- Final spreadsheet export produces XLSX + CSV
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

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
    monkeypatch.setenv("TWISTED_ENGINE_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("TWISTED_TOKEN", token)
    try:
        yield f"http://127.0.0.1:{port}/api", token, s
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        reset_settings(None)


def _hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
def test_procedure_metadata_exposes_all_5_stages(live_engine) -> None:
    base, token, _ = live_engine
    r = httpx.get(f"{base}/procedures", headers=_hdrs(token))
    assert r.status_code == 200
    bb = next(p for p in r.json() if p["id"] == "bb")
    stage_ids = sorted(s["id"] for s in bb["stages"])
    assert stage_ids == ["stage1", "stage2", "stage3", "stage4", "stage5"]
    # Each stage has at least one step
    for st in bb["stages"]:
        assert len(st["steps"]) >= 1


@pytest.mark.integration
def test_walkthrough_steps_routed_to_correct_runtime(live_engine) -> None:
    base, token, _ = live_engine
    # Set up an engagement
    r = httpx.post(f"{base}/engagements",
                   json={"client": "ACME", "primary_domain": "acme.example",
                         "scope": [{"kind": "wildcard", "pattern": "acme.example"}]},
                   headers=_hdrs(token))
    eng_id = r.json()["id"]

    # Queue a windows-only walkthrough (zap)
    r = httpx.post(f"{base}/steps/run",
                   json={"engagement_id": eng_id,
                         "step_id": "bb.stage4.zap_walkthrough"},
                   headers=_hdrs(token))
    assert r.status_code == 201

    # Linux worker registers WITHOUT 'zap' capability — should not get the job
    httpx.post(f"{base}/workers/register",
               json={"id": "wsl-1", "hostname": "x", "os": "linux",
                     "capabilities": ["nmap", "dig", "network"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "wsl-1", "runtime": "linux",
                          "capabilities": ["nmap", "dig", "network"]},
                  headers=_hdrs(token))
    assert r.json() is None

    # Windows worker WITH zap claims it
    httpx.post(f"{base}/workers/register",
               json={"id": "win-1", "hostname": "y", "os": "windows",
                     "capabilities": ["browser", "zap"]},
               headers=_hdrs(token)).raise_for_status()
    r = httpx.get(f"{base}/jobs/next",
                  params={"worker_id": "win-1", "runtime": "windows",
                          "capabilities": ["browser", "zap"]},
                  headers=_hdrs(token))
    assert r.json() is not None


@pytest.mark.integration
def test_full_bb_workflow_with_mocked_modules(live_engine) -> None:
    base, token, _ = live_engine
    from twisted.modules.recon import crtsh as crtsh_mod
    from twisted.modules.recon import dns_enum as dns_mod
    from twisted.modules.recon import email_security as email_mod

    # Seed engagement
    r = httpx.post(f"{base}/engagements",
                   json={"client": "ACME", "primary_domain": "acme.example",
                         "scope": [{"kind": "wildcard", "pattern": "acme.example"}]},
                   headers=_hdrs(token))
    eng_id = r.json()["id"]

    # Stage 1 — crt.sh, dns_enum, email_security via /steps/run + worker
    httpx.post(f"{base}/workers/register",
               json={"id": "wsl-1", "hostname": "ubuntu", "os": "linux",
                     "capabilities": ["network", "dig"]},
               headers=_hdrs(token)).raise_for_status()

    def _claim_and_run(step_id: str, patches: dict) -> None:
        r = httpx.post(f"{base}/steps/run",
                       json={"engagement_id": eng_id, "step_id": step_id},
                       headers=_hdrs(token))
        assert r.status_code == 201
        r = httpx.get(f"{base}/jobs/next",
                      params={"worker_id": "wsl-1", "runtime": "linux",
                              "capabilities": ["network", "dig"]},
                      headers=_hdrs(token))
        offer = r.json()
        assert offer is not None
        from contextlib import ExitStack

        from twisted.worker.dispatch import dispatch, serialise_result
        with ExitStack() as stack:
            for module, kwargs in patches.items():
                if kwargs:
                    stack.enter_context(patch.multiple(module, **kwargs))
            result = dispatch(offer)
        payload = serialise_result(result)
        r = httpx.post(f"{base}/jobs/{offer['job_id']}/result", json=payload,
                       headers=_hdrs(token))
        assert r.status_code == 200, r.text

    # crt.sh
    _claim_and_run("bb.stage1.crtsh", {
        crtsh_mod: {"_query_crtsh": lambda *a, **kw: [
            {"name_value": "api.acme.example\nstaging.acme.example\nweb.acme.example"}
        ]},
    })

    # dns_enum
    _claim_and_run("bb.stage1.dns_enum", {
        dns_mod: {
            "tool_available": lambda _name: True,
            "_dig": lambda host, rtype, **_: {"A": ["192.0.2.1"]}.get(rtype, []),
        },
    })

    # email_security with no records present (so it emits findings)
    _claim_and_run("bb.stage1.email_security", {
        email_mod: {
            "tool_available": lambda _name: True,
            "_txt": lambda *_a, **_kw: [],
        },
    })

    # Verify state
    r = httpx.get(f"{base}/engagements/{eng_id}/assets", headers=_hdrs(token))
    hosts = sorted(a["host"] for a in r.json())
    assert "api.acme.example" in hosts
    assert "staging.acme.example" in hosts
    assert "web.acme.example" in hosts

    r = httpx.get(f"{base}/engagements/{eng_id}/findings", headers=_hdrs(token))
    titles = [f["title"] for f in r.json()]
    assert any("Missing SPF" in t for t in titles)
    assert any("Missing DMARC" in t for t in titles)

    # Add some techs to the assets so risk scoring + nvd_lookup have data
    r = httpx.get(f"{base}/engagements/{eng_id}/assets/detail", headers=_hdrs(token))
    asset_ids = {a["host"]: a["id"] for a in r.json()}
    # Attach techs
    httpx.post(f"{base}/engagements/{eng_id}/assets/{asset_ids['api.acme.example']}/techs",
               json=[{"name": "Apache", "version": "2.4.41 (2019)"},
                     {"name": "PHP", "version": "7.2.26"}],
               headers=_hdrs(token)).raise_for_status()
    # Attach ports  -> need to do via a separate path; skip and just confirm risk scoring
    # works without ports.

    # Risk scoring -> uses _engine_callback module which makes HTTP calls.
    # Override its env settings so it points at our test engine.
    from twisted.core.settings import Settings as _S
    from twisted.core.settings import reset_settings as _r
    from twisted.modules.recon import risk_scoring as risk_mod
    new = _S()  # picks up TWISTED_ENGINE_URL/TWISTED_TOKEN env vars
    _r(new)
    try:
        # Drive risk_scoring directly (it's an "engine-aware" module that uses
        # EngineClient internally).
        from datetime import datetime

        from twisted.modules.base import ModuleContext
        ctx = ModuleContext(
            engagement_id=eng_id, step_id="bb.stage3.risk_score",
            procedure="bb", stage="stage3",
            params={"engagement_id": eng_id},
            work_dir=Path("/tmp/twisted_test_risk"),
            scope=None, timestamp=datetime.now(),
            worker_id="t", worker_host="wsl",
        )
        ctx.work_dir.mkdir(parents=True, exist_ok=True)
        result = risk_mod.run(ctx)
        assert result.success, result.error
        assert result.extra["scored"] >= 1
        # Asset risk_total updated
        r = httpx.get(f"{base}/engagements/{eng_id}/assets/detail", headers=_hdrs(token))
        api_asset = next(a for a in r.json() if a["host"] == "api.acme.example")
        assert api_asset["risk_total"] >= 1
        assert api_asset["risk_scores"]  # breakdown rows present

        # Report builder
        from twisted.modules.report import builder as report_mod
        ctx2 = ModuleContext(
            engagement_id=eng_id, step_id="bb.stage5.build_report",
            procedure="bb", stage="stage5",
            params={"engagement_id": eng_id, "formats": ["html", "markdown"]},
            work_dir=Path("/tmp/twisted_test_report"),
            scope=None, timestamp=datetime.now(),
            worker_id="t", worker_host="wsl",
        )
        ctx2.work_dir.mkdir(parents=True, exist_ok=True)
        result = report_mod.build(ctx2)
        assert result.success, result.error
        assert any(p.suffix == ".html" for p in result.artifacts)
        assert any(p.suffix == ".md" for p in result.artifacts)
        # Sanity: HTML has some content from the engagement
        html = next(p for p in result.artifacts if p.suffix == ".html").read_text()
        assert "ACME" in html
        assert "Missing SPF" in html or "Missing DMARC" in html

        # Spreadsheet exporter
        from twisted.modules.report import spreadsheet as ss_mod
        ctx3 = ModuleContext(
            engagement_id=eng_id, step_id="bb.stage5.export_findings",
            procedure="bb", stage="stage5",
            params={"engagement_id": eng_id},
            work_dir=Path("/tmp/twisted_test_export"),
            scope=None, timestamp=datetime.now(),
            worker_id="t", worker_host="wsl",
        )
        ctx3.work_dir.mkdir(parents=True, exist_ok=True)
        result = ss_mod.export(ctx3)
        assert result.success
        assert any(p.suffix == ".xlsx" for p in result.artifacts)
        assert any(p.suffix == ".csv" for p in result.artifacts)
    finally:
        _r(None)
