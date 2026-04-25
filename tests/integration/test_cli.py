"""CLI smoke tests via Typer's CliRunner.

Engine endpoints are exercised by booting a real uvicorn server in a
background thread on an ephemeral port — the most realistic transport.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from typer.testing import CliRunner

from twisted.core.settings import Settings, reset_settings
from twisted.engine.app import create_app
from twisted.engine.auth import ensure_token


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _UvicornInThread:
    def __init__(self, app, host: str, port: int) -> None:
        config = uvicorn.Config(app, host=host, port=port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        # Wait for readiness.
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.server.started:
                return
            time.sleep(0.05)
        raise TimeoutError("uvicorn failed to start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
    """Spin up a real engine on an ephemeral port for the CLI to hit."""
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
    server = _UvicornInThread(app, "127.0.0.1", port)
    server.start()
    engine_root = f"http://127.0.0.1:{port}"
    base_url = f"{engine_root}/api"
    monkeypatch.setenv("TWISTED_ENGINE_URL", engine_root)
    monkeypatch.setenv("TWISTED_TOKEN", token)
    try:
        # Quick sanity smoke
        r = httpx.get(f"{base_url}/health", timeout=2)
        r.raise_for_status()
        yield base_url, token
    finally:
        server.stop()
        reset_settings(None)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, *args: str):
    from twisted.cli.__main__ import app
    return runner.invoke(app, list(args))


class TestCli:
    def test_version(self, runner: CliRunner) -> None:
        result = _invoke(runner, "version")
        assert result.exit_code == 0
        assert "twisted-suite" in result.stdout

    def test_token_show_creates_token(self, cli_env, runner: CliRunner) -> None:
        result = _invoke(runner, "token", "show")
        assert result.exit_code == 0
        # token is a urlsafe base64-ish string, length > 20
        assert len(result.stdout.strip()) > 20

    def test_engagement_lifecycle(self, cli_env, runner: CliRunner) -> None:
        # New engagement
        result = _invoke(runner, "engagement", "new",
                         "--client", "ACME",
                         "--domain", "acme.example")
        assert result.exit_code == 0, result.stdout + result.stderr
        assert "Created" in result.stdout

        # List
        result = _invoke(runner, "engagement", "list")
        assert result.exit_code == 0
        assert "ACME" in result.stdout

        # Show by client name
        result = _invoke(runner, "engagement", "show", "ACME")
        assert result.exit_code == 0
        assert "acme.example" in result.stdout

    def test_procedure_list_includes_bb(self, cli_env, runner: CliRunner) -> None:
        result = _invoke(runner, "procedure", "list")
        assert result.exit_code == 0
        assert "bb" in result.stdout

    def test_step_run_then_list(self, cli_env, runner: CliRunner) -> None:
        # Need a worker registered for the queued step to do anything
        # interesting; for this CLI smoke we just check the queue + list paths.
        result = _invoke(runner, "engagement", "new", "--client", "ACME",
                         "--domain", "acme.example")
        assert result.exit_code == 0

        result = _invoke(runner, "step", "run",
                         "bb.stage1.crtsh",
                         "--engagement", "ACME")
        assert result.exit_code == 0
        assert "Queued" in result.stdout

        result = _invoke(runner, "step", "list", "-e", "ACME")
        assert result.exit_code == 0
        assert "bb.stage1.crtsh" in result.stdout

    def test_asset_list_empty_ok(self, cli_env, runner: CliRunner) -> None:
        _invoke(runner, "engagement", "new", "--client", "ACME")
        result = _invoke(runner, "asset", "list", "-e", "ACME")
        assert result.exit_code == 0


class TestSystemdInstall:
    def test_unit_writer_produces_correct_paths(self, tmp_path: Path,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
        from twisted.cli.systemd_install import install_user_unit

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "data"))
        monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / ".twisted/worker.token"))
        s = Settings()
        s.ensure_dirs()
        unit = install_user_unit(s)
        assert unit.exists()
        body = unit.read_text()
        assert "[Unit]" in body
        assert "twisted" in body
        assert str(s.data_root) in body
        assert str(s.token_file) in body
