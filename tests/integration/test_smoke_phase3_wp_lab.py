"""Phase 3 live smoke tests — drive ``ab`` and ``wrk`` against a
Dockerised WordPress lab so we can prove the wpstress wrappers parse
real benchmark-tool output.

Default behavior: SKIPPED. Opt in with::

    pytest -m "network and docker"

Each test additionally skips itself if any of:
- outbound networking is unavailable (needed to pull the WP image)
- the ``docker`` binary or ``docker compose`` plugin isn't installed
- the lab fails to come up within the startup budget
- the relevant load-test tool (``ab`` / ``wrk``) isn't installed

The lab compose file lives at ``docker/labs/wordpress/docker-compose.yml``
(WordPress + MariaDB, ports published on a free local port). The fixture
is ``module``-scoped so the container set is brought up once and
reused across the ab + wrk tests.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from twisted.core.runner import tool_available
from twisted.modules.base import ModuleContext
from twisted.modules.wpstress import ab_baseline, wrk_escalating

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker" / "labs" / "wordpress" / "docker-compose.yml"
PROJECT_NAME = "twisted_wp_smoke"
LAB_STARTUP_BUDGET_S = 180


def _has_internet() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=3):
            return True
    except OSError:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    # Docker Compose v2 is a docker subcommand; v1 was the legacy
    # ``docker-compose`` binary. We support either.
    if shutil.which("docker-compose") is not None:
        return True
    try:
        r = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _compose(*args: str, env: dict | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess:
    """Invoke `docker compose` (or legacy `docker-compose`) with the
    smoke-test project name + compose file pinned."""
    if shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, timeout=5,
    ).returncode == 0:
        base = ["docker", "compose"]
    else:
        base = ["docker-compose"]
    cmd = [*base, "-p", PROJECT_NAME, "-f", str(COMPOSE_FILE), *args]
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, env=full_env)


@pytest.fixture(scope="module", autouse=True)
def _require_internet_and_docker() -> None:
    if not _has_internet():
        pytest.skip("no outbound network available", allow_module_level=True)
    if not _docker_available():
        pytest.skip("docker / docker compose not installed", allow_module_level=True)
    if not COMPOSE_FILE.is_file():
        pytest.skip(f"compose file missing: {COMPOSE_FILE}", allow_module_level=True)


@pytest.fixture(scope="module")
def wordpress_lab() -> Iterator[str]:
    """Bring up the Docker WordPress lab and yield its base URL.

    Tears down ``-v`` so the MariaDB volume doesn't survive the run.
    """
    port = _free_port()
    env = {"WP_PORT": str(port)}

    up = _compose("up", "-d", "--wait", env=env, timeout=LAB_STARTUP_BUDGET_S)
    if up.returncode != 0:
        # Surface compose stderr to the skip reason so the user can see
        # what went wrong (image pull failure, port collision, etc).
        _compose("down", "-v", env=env, timeout=60)
        pytest.skip(
            f"docker compose up failed (rc={up.returncode}):\n"
            f"stdout: {up.stdout[-500:]}\nstderr: {up.stderr[-500:]}",
            allow_module_level=True,
        )

    base_url = f"http://127.0.0.1:{port}/"
    deadline = time.time() + 60
    last_err: str | None = None
    while time.time() < deadline:
        try:
            import urllib.request
            with urllib.request.urlopen(base_url, timeout=3) as r:
                if r.status < 500:
                    break
                last_err = f"status {r.status}"
        except Exception as e:  # noqa: BLE001
            last_err = str(e)[:120]
        time.sleep(2)
    else:
        _compose("down", "-v", env=env, timeout=60)
        pytest.skip(
            f"WordPress lab failed to respond at {base_url} within 60s "
            f"(last error: {last_err})",
            allow_module_level=True,
        )

    try:
        yield base_url
    finally:
        _compose("down", "-v", env=env, timeout=60)


def _ctx(tmp_path: Path, step_id: str, params: dict) -> ModuleContext:
    work = tmp_path / step_id.replace(".", "_")
    work.mkdir(parents=True, exist_ok=True)
    return ModuleContext(
        engagement_id=1,
        step_id=step_id,
        procedure="wp_stress",
        stage="phase_smoke",
        params=params,
        work_dir=work,
        scope=None,
        timestamp=datetime.now(),
        worker_id="smoke-test",
        worker_host="wsl",
    )


# ──────────────────────────── ab baseline ────────────────────────────


@pytest.mark.network
@pytest.mark.docker
@pytest.mark.integration
def test_ab_baseline_against_wp_lab(tmp_path: Path, wordpress_lab: str) -> None:
    """`ab` against the local WP lab parses to a populated metrics dict
    with rps, mean_ms, and p99_ms all present."""
    if not tool_available("ab"):
        pytest.skip("ab not installed (apt install apache2-utils)")

    ctx = _ctx(
        tmp_path,
        "wp_stress.phase1.baseline_ab",
        {
            "url": wordpress_lab,
            "requests": 50,
            "concurrency": 2,
            "timeout": 60,
        },
    )
    result = ab_baseline.run(ctx)
    assert result.success, result.error

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    payload = json.loads(json_path.read_text())
    metrics = payload["metrics"]

    # All canonical metrics must have parsed
    for key in ("requests_per_sec", "mean_ms", "complete"):
        assert key in metrics, f"ab parser missing {key}; got {sorted(metrics)}"

    assert metrics["complete"] >= 1, "ab reported zero completed requests"
    assert metrics["requests_per_sec"] > 0, "rps should be positive"
    assert metrics["mean_ms"] > 0, "mean latency should be positive"

    # error_rate is derived only if both `complete` and `failed_requests`
    # parsed. ab always prints "Failed requests:" so it should be there.
    assert "error_rate" in metrics, (
        f"error_rate missing — likely 'Failed requests:' line not parsed. "
        f"got: {sorted(metrics)}"
    )
    # WP install screen is a 200/302; tolerate small percentage of
    # mismatched non-2xx since wp redirects to /wp-admin/install.php
    assert metrics["error_rate"] <= 1.0


# ──────────────────────────── wrk escalating ────────────────────────────


@pytest.mark.network
@pytest.mark.docker
@pytest.mark.integration
def test_wrk_escalating_against_wp_lab(tmp_path: Path, wordpress_lab: str) -> None:
    """`wrk` against the local WP lab parses to populated per-round
    metrics, and the escalating runner stops on saturation OR completes
    all rounds without crashing."""
    if not tool_available("wrk"):
        pytest.skip("wrk not installed")

    ctx = _ctx(
        tmp_path,
        "wp_stress.phase2.wrk_escalating",
        {
            "url": wordpress_lab,
            "duration": 3,         # short rounds keep the test under ~15s
            "threads": 2,
            "rounds": [2, 5],      # only two rounds — enough to exercise the loop
            "timeout": 30,
        },
    )
    result = wrk_escalating.run(ctx)
    assert result.success, result.error

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    summary = json.loads(json_path.read_text())

    assert summary["url"] == wordpress_lab
    assert summary["rounds"], "no rounds recorded"
    # Either we ran every round, or we stopped early on a saturation
    # heuristic — both are valid outcomes for the smoke test.
    assert len(summary["rounds"]) <= 2

    first = summary["rounds"][0]
    assert first["connections"] == 2
    metrics = first["metrics"]

    # wrk's "Requests/sec:" line must always parse
    assert "requests_per_sec" in metrics, (
        f"wrk parser missing 'requests_per_sec'; got {sorted(metrics)}"
    )
    rps = metrics["requests_per_sec"]
    assert isinstance(rps, (int, float)) and rps > 0, f"rps={rps!r}"

    # Per-round .txt artifact should exist for each round
    txt_artifacts = [p for p in result.artifacts if p.suffix == ".txt"]
    assert len(txt_artifacts) == len(summary["rounds"])
    for p in txt_artifacts:
        assert p.read_text().strip(), f"empty wrk artifact: {p}"
