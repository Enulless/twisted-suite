"""Phase 6 — CLI training commands smoke tests.

Boots a real engine on an ephemeral port (mirroring test_cli.py), then
exercises ``twisted train list`` / ``train show`` / ``train extract``.
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


@pytest.fixture
def cli_env(tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
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
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 5
    while time.time() < deadline and not server.started:
        time.sleep(0.05)
    base_url = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("TWISTED_ENGINE_URL", base_url)
    monkeypatch.setenv("TWISTED_TOKEN", token)
    httpx.get(f"{base_url}/health", timeout=2).raise_for_status()
    try:
        yield base_url, token
    finally:
        server.should_exit = True
        th.join(timeout=5)
        reset_settings(None)


def _invoke(*args: str):
    from twisted.cli.__main__ import app
    return CliRunner().invoke(app, list(args))


@pytest.mark.integration
def test_train_list_renders(cli_env) -> None:
    result = _invoke("train", "list", "--user", "alice")
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    # Rich's Table truncates the step_id column, so assert on the
    # ellipsised prefix that always survives.
    assert "bb.stage1.crt" in result.stdout
    assert "Certificate" in result.stdout
    # Quiz column shows 'yes' for crtsh (we shipped a quiz for it)
    assert "yes" in result.stdout


@pytest.mark.integration
def test_train_list_filtered_by_procedure(cli_env) -> None:
    result = _invoke("train", "list", "--procedure", "wifi")
    assert result.exit_code == 0
    assert "wifi" in result.stdout
    assert "phase1" in result.stdout
    # bb shouldn't be in a wifi-only listing
    assert "bb.stage1" not in result.stdout


@pytest.mark.integration
def test_train_show_renders_lesson(cli_env) -> None:
    result = _invoke("train", "show", "bb.stage1.crtsh")
    assert result.exit_code == 0
    assert "Certificate Transparency" in result.stdout or "CT log" in result.stdout
    # Footer mentions a quiz is available
    assert "twisted train quiz" in result.stdout


@pytest.mark.integration
def test_train_progress_summary(cli_env) -> None:
    result = _invoke("train", "progress", "--user", "alice")
    assert result.exit_code == 0
    # Summary has each procedure with a 0/N completed line
    assert "bb" in result.stdout
    assert "completed" in result.stdout


@pytest.mark.integration
def test_train_extract_help(cli_env) -> None:
    """Smoke: --help works (we don't run the actual extract because
    that needs the real .docx files which aren't always present)."""
    result = _invoke("train", "extract", "--help")
    assert result.exit_code == 0
    assert "--bb" in result.stdout
    assert "--wp" in result.stdout
    assert "--wifi" in result.stdout
