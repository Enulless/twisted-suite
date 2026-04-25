"""Path translation between WSL POSIX form and Windows native form.

Rule: every path stored in the database is in POSIX/WSL form
(``/mnt/c/Users/awhwt/...`` or ``/home/<user>/...``). Workers running on the
Windows side convert those to ``C:\\Users\\awhwt\\...`` only when invoking
Windows-native tools, and convert back when reporting artifact locations.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PureWindowsPath

# /mnt/<drive>/... where drive is a single letter
_WSL_MOUNT_RE = re.compile(r"^/mnt/([a-zA-Z])(/|$)(.*)")
# <Drive>:\... or <Drive>:/...
_WIN_DRIVE_RE = re.compile(r"^([a-zA-Z]):[\\/](.*)")


def is_wsl() -> bool:
    """Return True when running inside the WSL kernel.

    Detection mirrors the upstream convention: the kernel release string
    contains ``microsoft`` on every WSL build.
    """
    if os.environ.get("TWISTED_FORCE_WSL") == "1":
        return True
    if os.environ.get("TWISTED_FORCE_WSL") == "0":
        return False
    try:
        with open("/proc/sys/kernel/osrelease") as fp:
            return "microsoft" in fp.read().lower()
    except OSError:
        return False


def is_windows() -> bool:
    """Return True when running on a native Windows Python interpreter."""
    return os.name == "nt"


def to_wsl(path: str | os.PathLike) -> str:
    """Convert a Windows-style path to WSL POSIX form.

    Idempotent: a path that already looks WSL-style is returned as-is
    (with backslashes flipped where needed).
    """
    raw = str(path)
    if not raw:
        return raw

    # Already WSL-style.
    if raw.startswith("/"):
        return raw.replace("\\", "/")

    # UNC: \\wsl$\Ubuntu\home\foo  ->  /home/foo
    unc = re.match(r"^\\\\wsl\$\\[^\\]+\\(.*)", raw, re.IGNORECASE)
    if unc:
        return "/" + unc.group(1).replace("\\", "/")
    unc2 = re.match(r"^\\\\wsl\.localhost\\[^\\]+\\(.*)", raw, re.IGNORECASE)
    if unc2:
        return "/" + unc2.group(1).replace("\\", "/")

    m = _WIN_DRIVE_RE.match(raw)
    if m:
        drive, rest = m.group(1).lower(), m.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}".rstrip("/") if rest else f"/mnt/{drive}/"

    # Relative path — leave it alone, just normalise separators.
    return raw.replace("\\", "/")


def to_windows(path: str | os.PathLike) -> str:
    """Convert a WSL POSIX path to Windows native form.

    Non-/mnt POSIX paths (e.g. /home/null/foo) are translated through the
    ``\\\\wsl$\\Ubuntu\\...`` UNC convention so they remain usable from the
    Windows side. The distro name defaults to ``Ubuntu`` and may be
    overridden via the ``TWISTED_WSL_DISTRO`` environment variable.
    """
    raw = str(path)
    if not raw:
        return raw

    # Already Windows-style.
    if _WIN_DRIVE_RE.match(raw) or raw.startswith("\\\\"):
        return str(PureWindowsPath(raw))

    # /mnt/<drive>/...
    m = _WSL_MOUNT_RE.match(raw)
    if m:
        drive, _, rest = m.group(1).upper(), m.group(2), m.group(3)
        return str(PureWindowsPath(f"{drive}:\\") / rest.replace("/", "\\")) if rest else f"{drive}:\\"

    # Other POSIX absolute path -> UNC into the WSL distro.
    if raw.startswith("/"):
        distro = os.environ.get("TWISTED_WSL_DISTRO", "Ubuntu")
        rest = raw.lstrip("/").replace("/", "\\")
        return f"\\\\wsl$\\{distro}\\{rest}"

    # Relative path — leave alone.
    return raw.replace("/", "\\")


def to_native(path: str | os.PathLike) -> str:
    """Convert path to whatever form the *current* host expects.

    On WSL/Linux returns POSIX form. On Windows returns ``C:\\...`` form.
    Use this whenever shelling out to a tool installed on the current host.
    """
    if is_windows():
        return to_windows(path)
    return to_wsl(path)


def to_canonical(path: str | os.PathLike) -> str:
    """Convert path to canonical (POSIX/WSL) form for storage in the DB."""
    return to_wsl(path)


def normalise(path: str | os.PathLike) -> Path:
    """Return a Path in canonical form, resolved to absolute when possible."""
    canonical = to_canonical(path)
    p = Path(canonical)
    try:
        return p.resolve()
    except (OSError, RuntimeError):
        return p
