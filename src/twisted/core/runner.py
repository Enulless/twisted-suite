"""Subprocess wrapper + tool detection.

Generalised port of ``run_cmd`` and ``tool_available`` from recon_ovh.py.
Uses platform-aware command lookup so the same code works in WSL and on
Windows (e.g. ``wpscan`` may be ``wpscan.bat`` on Windows).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .paths import is_windows, to_native


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    def combined_output(self) -> str:
        out = self.stdout.strip()
        err = self.stderr.strip()
        if err:
            out = f"{out}\n{err}".strip()
        return out


def tool_available(name: str) -> bool:
    """Return True iff ``name`` resolves on the current PATH.

    Honours ``which`` semantics on POSIX and ``where`` semantics on Windows.
    """
    return shutil.which(name) is not None


def find_tools(*names: str) -> dict[str, str | None]:
    """Resolve a set of tool names to their absolute paths (or None)."""
    return {name: shutil.which(name) for name in names}


def run_cmd(
    cmd: list[str] | str,
    *,
    timeout: int = 30,
    cwd: str | os.PathLike | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    capture: bool = True,
    check: bool = False,
) -> CommandResult:
    """Run a subprocess and return a structured result.

    Differences from raw ``subprocess.run``:
    - Always returns a CommandResult (no exceptions for non-zero exits unless
      ``check=True``).
    - Distinguishes timeouts and FileNotFoundError from other failures.
    - Timestamps the call so we can record duration in step artifacts.
    - Translates path arguments where needed (no-op when same host).
    """
    if isinstance(cmd, str):
        # Honour shlex.split semantics for convenience.
        import shlex
        argv = shlex.split(cmd)
    else:
        argv = list(cmd)

    if not argv:
        return CommandResult(cmd=argv, returncode=None, stdout="", stderr="", duration_ms=0,
                             error="empty command")

    # Translate path arguments to the native form for the current host.
    translated = [argv[0]] + [
        to_native(a) if isinstance(a, (str, Path)) and ("/" in str(a) or "\\" in str(a)) else str(a)
        for a in argv[1:]
    ]

    start = time.monotonic()
    try:
        completed = subprocess.run(
            translated,
            capture_output=capture,
            text=True,
            input=input_text,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            check=check,
            shell=False,
        )
    except subprocess.TimeoutExpired as e:
        duration = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=translated,
            returncode=None,
            stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
            stderr=(e.stderr or "") if isinstance(e.stderr, str) else "",
            duration_ms=duration,
            timed_out=True,
            error=f"timeout after {timeout}s",
        )
    except FileNotFoundError:
        duration = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=translated,
            returncode=None,
            stdout="",
            stderr="",
            duration_ms=duration,
            error=f"tool not installed: {translated[0]}",
        )
    except subprocess.CalledProcessError as e:
        duration = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=translated,
            returncode=e.returncode,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
            duration_ms=duration,
            error=f"non-zero exit: {e.returncode}",
        )
    except Exception as e:  # noqa: BLE001 - we genuinely want a fallback for unexpected exceptions
        duration = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=translated,
            returncode=None,
            stdout="",
            stderr="",
            duration_ms=duration,
            error=str(e)[:200],
        )

    duration = int((time.monotonic() - start) * 1000)
    return CommandResult(
        cmd=translated,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_ms=duration,
    )


@dataclass
class CapabilityProbe:
    """Detect tools relevant to a runtime (linux | windows)."""

    runtime: str
    detectors: dict[str, Callable[[], bool]] = field(default_factory=dict)

    def probe(self) -> list[str]:
        return sorted(name for name, fn in self.detectors.items() if fn())


def default_linux_capabilities() -> list[str]:
    """The capabilities we look for on a WSL/Linux worker."""
    tools = [
        "dig", "whois", "openssl", "curl", "nmap", "nikto", "sqlmap",
        "subfinder", "amass", "assetfinder", "sublist3r", "httpx",
        "wpscan", "ab", "wrk", "locust",
        "airmon-ng", "airodump-ng", "aireplay-ng", "hashcat", "hcxpcapngtool",
        "wash", "reaver", "bully", "responder", "crackmapexec", "enum4linux-ng",
        "snmpwalk", "hydra", "testssl.sh",
    ]
    found = [t for t in tools if tool_available(t)]
    found.append("network")
    found.append("python")
    return sorted(set(found))


def default_windows_capabilities() -> list[str]:
    """Capabilities a Windows worker can credibly claim.

    The exact GUI tool detection is approximate (PATH-based); the dashboard
    surfaces ``capabilities`` so the operator can verify before scheduling.
    """
    tools = [
        "curl", "openssl", "powershell", "pwsh", "code",
        "zap", "burp", "postman", "nmap", "wireshark",
    ]
    found = [t for t in tools if tool_available(t)]
    found.extend(["browser", "screenshots", "windows"])
    if is_windows():
        found.append("native-windows")
    return sorted(set(found))
