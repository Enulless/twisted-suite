"""Tests for the OVH first-engagement import script."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn

from twisted.cli.import_ovh import (
    DEFAULT_DOMAIN,
    assets_from_artifacts,
    discover_artifacts,
    run_import,
)
from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token

# ──────────────────────────── unit ────────────────────────────


@pytest.fixture
def fake_twisted_root(tmp_path: Path) -> Path:
    root = tmp_path / "Twisted"
    (root / "OVHcloud").mkdir(parents=True)
    (root / "recon_ovh_20260424_224855").mkdir()
    # Create some files matching the expected naming pattern
    (root / "OVHcloud" / "step1_api_port_probe_20260424_232040.json").write_text(
        json.dumps({
            "target": "api.soyoustart.com",
            "ports": {"8080": {"tcp_open": False, "http_probes": []}},
        })
    )
    (root / "OVHcloud" / "step1_api_port_probe_20260424_232040.txt").write_text("port probe summary")
    (root / "OVHcloud" / "step2_forum_banner_grab_20260424_233133.json").write_text(
        json.dumps({"hosts": ["forum.ovh.com", "manager.ovh.com"], "data": "..."})
    )
    (root / "recon_ovh_20260424_224855" / "01_subdomains.txt").write_text(
        "api.ovh.com\nwww.ovh.com\neu.soyoustart.com\n"
    )
    (root / "recon_ovh_20260424_224855" / "02_dns.json").write_text(
        json.dumps({"api.ovh.com": {"A": ["1.2.3.4"]}, "ca.soyoustart.com": {"A": ["1.2.3.5"]}})
    )
    return root


class TestDiscovery:
    def test_finds_step_files(self, fake_twisted_root: Path) -> None:
        artifacts = discover_artifacts(fake_twisted_root)
        names = {p.name for p in artifacts}
        assert "step1_api_port_probe_20260424_232040.json" in names
        assert "step2_forum_banner_grab_20260424_233133.json" in names
        # No duplicates
        assert len(artifacts) == len(set(artifacts))

    def test_handles_missing_root(self, tmp_path: Path) -> None:
        result = discover_artifacts(tmp_path / "nope")
        assert result == []


class TestAssetExtraction:
    def test_extracts_subdomains_matching_root(self, fake_twisted_root: Path) -> None:
        artifacts = discover_artifacts(fake_twisted_root)
        assets = assets_from_artifacts(artifacts, DEFAULT_DOMAIN)
        # Bare 'ovh.com' isn't extracted (no leading subdomain) but children are
        assert "forum.ovh.com" in assets
        assert "manager.ovh.com" in assets
        assert "api.ovh.com" in assets
        # Won't find soyoustart in a *.ovh.com extraction
        assert "eu.soyoustart.com" not in assets


# ──────────────────────────── integration ────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def engine_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
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
    engine_root = f"http://127.0.0.1:{port}"
    base = f"{engine_root}/api"
    monkeypatch.setenv("TWISTED_ENGINE_URL", engine_root)
    monkeypatch.setenv("TWISTED_TOKEN", token)
    try:
        yield base, token, engine_root
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        reset_settings(None)


class TestRunImport:
    def test_dry_run_lists_artifacts_and_assets(self, fake_twisted_root: Path) -> None:
        out = run_import(twisted_root=fake_twisted_root, dry_run=True)
        assert out["artifact_count"] >= 4
        assert "candidate_assets" in out
        assert any("ovh.com" in a for a in out["assets"])

    def test_full_import_creates_engagement_and_assets(
        self, fake_twisted_root: Path, engine_server, monkeypatch
    ) -> None:
        base, token, engine_root = engine_server
        # `engine_url` goes to EngineClient which auto-prefixes /api,
        # so pass the bare host:port; `base` is the api-prefixed URL
        # used for direct httpx calls in the test body.
        out = run_import(
            twisted_root=fake_twisted_root,
            client_name="OVH",
            engine_url=engine_root,
            token=token,
        )
        assert out.get("engagement_id")
        # Verify via API
        r = httpx.get(f"{base}/engagements", headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        assert any(e["client"] == "OVH" for e in r.json())

        eng_id = out["engagement_id"]
        r = httpx.get(f"{base}/engagements/{eng_id}/assets",
                      headers={"Authorization": f"Bearer {token}"})
        hosts = sorted(a["host"] for a in r.json())
        assert "api.ovh.com" in hosts
        assert "forum.ovh.com" in hosts
        # api.ovh.com is in scope (exact match), forum.ovh.com is not (no wildcard for ovh.com)
        statuses = {a["host"]: a["in_scope"] for a in r.json()}
        assert statuses["api.ovh.com"] is True
        assert statuses["forum.ovh.com"] is False
