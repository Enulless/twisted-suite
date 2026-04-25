"""Shared bearer-token auth for the engine API.

The token is generated on first run and persisted at ``settings.token_file``.
Workers and the CLI read the same file (Windows side reads it via the
``\\\\wsl$\\Ubuntu\\home\\<you>\\.twisted\\worker.token`` UNC path) and send
``Authorization: Bearer <token>`` on every request.
"""

from __future__ import annotations

import contextlib
import os
import secrets

from fastapi import Depends, HTTPException, Request, status

from ..core.settings import Settings, get_settings


def ensure_token(settings: Settings | None = None) -> str:
    """Return the worker token, creating one if it doesn't exist yet."""
    s = settings or get_settings()
    s.token_file.parent.mkdir(parents=True, exist_ok=True)
    if s.token_file.exists():
        token = s.token_file.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    s.token_file.write_text(token)
    with contextlib.suppress(OSError):
        os.chmod(s.token_file, 0o600)
    return token


def read_token(settings: Settings | None = None) -> str | None:
    """Read the token file without auto-creating one."""
    s = settings or get_settings()
    if not s.token_file.exists():
        return None
    val = s.token_file.read_text().strip()
    return val or None


def require_token(request: Request) -> str:
    """FastAPI dependency: enforce ``Authorization: Bearer <token>``."""
    expected = read_token() or ""
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    presented = auth.split(None, 1)[1].strip()
    if not expected or not secrets.compare_digest(presented, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")
    return presented


# Convenience for routers
require_token_dep = Depends(require_token)
