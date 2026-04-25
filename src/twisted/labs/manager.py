"""Docker-compose lab manager.

Pure-Python wrapper around ``docker compose`` (or legacy
``docker-compose``) that knows how to bring each registered lab
up/down, query its status, and tail its logs. Designed so the engine
process can stay running on a host *without* docker; every operation
returns a structured result with ``available=False`` instead of
raising in that case.

Convention for compose files: each lab lives under
``<repo>/docker/labs/<lab_id>/docker-compose.yml`` and accepts a
``${<X>_PORT}`` env var that sets the host port.
"""

from __future__ import annotations

import enum
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# ──────────────────────────── Catalogue ────────────────────────────


@dataclass(frozen=True)
class LabSpec:
    """Static metadata about a lab. Loaded into ``LAB_CATALOGUE``."""

    id: str
    name: str
    description: str
    compose_relpath: str       # e.g. "docker/labs/dvwa/docker-compose.yml"
    project_name: str          # docker compose project namespace
    port_env: str              # name of the ${X_PORT} env var
    default_port: int          # the value if the env var is unset
    target_path: str = "/"     # http://127.0.0.1:<port><target_path>
    practice_for: tuple[str, ...] = field(default_factory=tuple)
    """Step ids whose 'Practice on the lab' button maps to this lab."""

    @property
    def target_url(self) -> str:
        # Resolved at runtime; the env var may override default_port.
        port = int(os.environ.get(self.port_env, self.default_port))
        return f"http://127.0.0.1:{port}{self.target_path}"


# Repo root resolution: the compose files ship with the repo, not the
# installed wheel. We walk up from this file until we hit a ``docker``
# directory sibling — works for both editable installs (most common)
# and tests run from a checkout.
def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "docker" / "labs").is_dir():
            return parent
    return here.parent.parent.parent.parent  # best-effort fallback


REPO_ROOT = _repo_root()


LAB_CATALOGUE: dict[str, LabSpec] = {
    "dvwa": LabSpec(
        id="dvwa",
        name="Damn Vulnerable Web Application",
        description=(
            "Classic PHP/MySQL teaching app with deliberate SQLi, XSS, "
            "command injection, file upload, CSRF, and IDOR vulnerabilities."
        ),
        compose_relpath="docker/labs/dvwa/docker-compose.yml",
        project_name="twisted_dvwa",
        port_env="DVWA_PORT",
        default_port=18081,
        target_path="/",
        practice_for=(
            "bb.stage3.http_probe",
            "bb.stage3.headers_audit",
            "bb.stage4.nikto",
            "bb.stage4.sqlmap_walkthrough",
            "bb.stage4.zap_walkthrough",
        ),
    ),
    "juice_shop": LabSpec(
        id="juice_shop",
        name="OWASP Juice Shop",
        description=(
            "Modern JavaScript single-page vulnerable app from OWASP. "
            "Covers the full OWASP Top 10 with CTF-style challenges."
        ),
        compose_relpath="docker/labs/juice_shop/docker-compose.yml",
        project_name="twisted_juice",
        port_env="JUICE_PORT",
        default_port=18082,
        target_path="/",
        practice_for=(
            "bb.stage3.http_probe",
            "bb.stage3.headers_audit",
            "bb.stage3.tls_audit",
            "bb.stage4.zap_walkthrough",
        ),
    ),
    "wordpress": LabSpec(
        id="wordpress",
        name="WordPress (vulnerable test instance)",
        description=(
            "Stock WordPress + MariaDB stack on tmpfs. The Phase 3 "
            "stress-test smoke fixtures bring this same lab up "
            "automatically."
        ),
        compose_relpath="docker/labs/wordpress/docker-compose.yml",
        project_name="twisted_wp",
        port_env="WP_PORT",
        default_port=18080,
        target_path="/",
        practice_for=(
            "wp_stress.phase1.baseline_ab",
            "wp_stress.phase2.escalating",
            "wp_stress.phase2.endpoint_stress",
            "wp_stress.phase3.wpscan",
            "wp_stress.phase3.exposed_files",
            "wp_stress.phase3.headers_diff",
        ),
    ),
    "metasploitable": LabSpec(
        id="metasploitable",
        name="Metasploitable 2",
        description=(
            "Full vulnerable Linux box exposing SSH, FTP, SMB, HTTP, "
            "and VNC on isolated host ports. Covers post-exploitation "
            "exercises (responder, crackmapexec, enum4linux)."
        ),
        compose_relpath="docker/labs/metasploitable/docker-compose.yml",
        project_name="twisted_msf2",
        port_env="MS_HTTP_PORT",
        default_port=18083,
        target_path="/",
        practice_for=(
            "wifi.phase4.responder_walkthrough",
            "wifi.phase4.crackmapexec_walkthrough",
            "wifi.phase4.enum4linux_walkthrough",
        ),
    ),
}


def get_lab(lab_id: str) -> LabSpec:
    if lab_id not in LAB_CATALOGUE:
        raise KeyError(lab_id)
    return LAB_CATALOGUE[lab_id]


def list_labs() -> list[LabSpec]:
    return list(LAB_CATALOGUE.values())


def lab_for_step(step_id: str) -> LabSpec | None:
    """Find the lab that advertises ``step_id`` as a practice target.
    Returns the first match (the catalogue order is intentional)."""
    for spec in LAB_CATALOGUE.values():
        if step_id in spec.practice_for:
            return spec
    return None


# ──────────────────────────── Status / errors ────────────────────────────


class LabState(enum.StrEnum):
    UP = "up"
    DOWN = "down"
    PARTIAL = "partial"   # some containers up, some down
    UNKNOWN = "unknown"


@dataclass
class LabStatus:
    spec: LabSpec
    state: LabState
    services: dict[str, str] = field(default_factory=dict)  # name → state string
    target_url: str | None = None


@dataclass
class LabResult:
    """Return value for up/down/logs operations."""
    success: bool
    available: bool                       # docker installed + reachable?
    state: LabState | None = None
    output: str = ""
    error: str | None = None


class LabError(RuntimeError):
    pass


# ──────────────────────────── Docker shell ────────────────────────────


def _docker_compose_cmd() -> list[str] | None:
    """Resolve which compose CLI flavour to use, or ``None`` if neither
    exists on PATH."""
    if shutil.which("docker") is None:
        return None
    try:
        r = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return ["docker", "compose"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if shutil.which("docker-compose") is not None:
        return ["docker-compose"]
    return None


def docker_available() -> bool:
    return _docker_compose_cmd() is not None


def _run_compose(spec: LabSpec, *args: str, env: dict | None = None,
                 timeout: int = 180) -> subprocess.CompletedProcess:
    base = _docker_compose_cmd()
    if base is None:
        raise LabError("docker / docker compose not installed")
    compose_path = REPO_ROOT / spec.compose_relpath
    if not compose_path.is_file():
        raise LabError(f"compose file missing: {compose_path}")
    cmd = [*base, "-p", spec.project_name, "-f", str(compose_path), *args]
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, env=full_env)


def _parse_ps_output(text: str) -> dict[str, str]:
    """Parse ``docker compose ps --format ...`` output into name→state.

    Falls back to parsing ``Name`` + ``State`` columns from the
    space-padded plain-text output if the JSON-formatted variant
    isn't available.
    """
    services: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("NAME", "Name", "name")):
            continue
        # Try JSON-line format: each line is a JSON object
        if line.startswith("{") and line.endswith("}"):
            import json
            try:
                row = json.loads(line)
            except ValueError:
                continue
            name = row.get("Name") or row.get("Service") or ""
            state = row.get("State") or row.get("Status") or "unknown"
            if name:
                services[name] = state.lower()
            continue
        # Otherwise, take name (1st col) and look for "Up" / "Exit" anywhere
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            state = "up" if "Up" in line or "running" in line.lower() else \
                    ("exited" if "Exit" in line or "exited" in line.lower()
                     else "unknown")
            services[name] = state
    return services


# ──────────────────────────── Operations ────────────────────────────


def lab_status(spec: LabSpec) -> LabStatus:
    if not docker_available():
        return LabStatus(spec=spec, state=LabState.UNKNOWN,
                         target_url=spec.target_url)
    try:
        r = _run_compose(spec, "ps", "--format", "json", timeout=15)
    except (LabError, subprocess.TimeoutExpired):
        return LabStatus(spec=spec, state=LabState.UNKNOWN,
                         target_url=spec.target_url)
    services = _parse_ps_output(r.stdout)
    if not services:
        return LabStatus(spec=spec, state=LabState.DOWN, services={},
                         target_url=spec.target_url)
    states = set(services.values())
    if states == {"up"} or states == {"running"}:
        state = LabState.UP
    elif "up" in states or "running" in states:
        state = LabState.PARTIAL
    else:
        state = LabState.DOWN
    return LabStatus(spec=spec, state=state, services=services,
                     target_url=spec.target_url)


def lab_up(spec: LabSpec, *, port: int | None = None,
           wait_seconds: int = 0, env: dict | None = None) -> LabResult:
    if not docker_available():
        return LabResult(success=False, available=False,
                         error="docker / docker compose not installed")
    env = dict(env or {})
    if port is not None:
        env[spec.port_env] = str(port)
    args = ["up", "-d"]
    if wait_seconds > 0:
        args.append("--wait")
    try:
        r = _run_compose(spec, *args, env=env,
                         timeout=max(180, wait_seconds + 60))
    except subprocess.TimeoutExpired as e:
        return LabResult(success=False, available=True,
                         error=f"compose up timed out after {e.timeout}s")
    except LabError as e:
        return LabResult(success=False, available=True, error=str(e))
    output = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        return LabResult(success=False, available=True, output=output[-2000:],
                         error=f"compose up rc={r.returncode}")
    status = lab_status(spec)
    return LabResult(success=True, available=True, state=status.state,
                     output=output[-500:])


def take_lab_down(spec: LabSpec, *, volumes: bool = True) -> LabResult:
    if not docker_available():
        return LabResult(success=False, available=False,
                         error="docker / docker compose not installed")
    args = ["down"]
    if volumes:
        args.append("-v")
    try:
        r = _run_compose(spec, *args, timeout=120)
    except subprocess.TimeoutExpired:
        return LabResult(success=False, available=True,
                         error="compose down timed out")
    except LabError as e:
        return LabResult(success=False, available=True, error=str(e))
    output = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        return LabResult(success=False, available=True, output=output[-2000:],
                         error=f"compose down rc={r.returncode}")
    return LabResult(success=True, available=True, state=LabState.DOWN,
                     output=output[-500:])


def lab_logs(spec: LabSpec, *, tail: int = 100) -> LabResult:
    if not docker_available():
        return LabResult(success=False, available=False,
                         error="docker / docker compose not installed")
    try:
        r = _run_compose(spec, "logs", f"--tail={tail}", timeout=30)
    except subprocess.TimeoutExpired:
        return LabResult(success=False, available=True,
                         error="compose logs timed out")
    except LabError as e:
        return LabResult(success=False, available=True, error=str(e))
    return LabResult(success=r.returncode == 0, available=True,
                     output=r.stdout or r.stderr or "")


def iter_logs(spec: LabSpec, *, tail: int = 100) -> Iterator[str]:
    """Generator form for SSE streaming (future use)."""
    result = lab_logs(spec, tail=tail)
    yield from result.output.splitlines()
