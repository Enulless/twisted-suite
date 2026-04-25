"""Shared bearer-token auth for the engine API.

The token is generated on first run and persisted at ``settings.token_file``.
Workers and the CLI read the same file (Windows side reads it via the
``\\\\wsl$\\Ubuntu\\home\\<you>\\.twisted\\worker.token`` UNC path) and send
``Authorization: Bearer <token>`` on every request.

The browser SPA uses the same token but stores it in an HttpOnly cookie
(``twisted_token``) set by ``POST /login``. ``require_token`` accepts
either the bearer header OR the cookie so both paths converge here.
"""

from __future__ import annotations

import contextlib
import os
import secrets

from fastapi import Depends, HTTPException, Request, status

from ..core.settings import Settings, get_settings

# Same cookie name the dashboard's ``POST /login`` sets via web_auth.py.
# Defined here too (instead of importing) to avoid a circular import:
# web_auth depends on this module's read_token().
SESSION_COOKIE_NAME = "twisted_token"


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
    """FastAPI dependency: enforce a valid token.

    Accepts either ``Authorization: Bearer <token>`` (the workers, CLI,
    and curl path) OR the ``twisted_token`` HttpOnly cookie set by the
    dashboard's ``POST /login`` (the browser SPA path). Both carry the
    same token value; this is purely about transport.
    """
    expected = read_token() or ""
    if not expected:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="engine has no token configured")

    # Header path (workers / CLI / tests with explicit headers)
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        presented = auth.split(None, 1)[1].strip()
        if presented and secrets.compare_digest(presented, expected):
            return presented

    # Cookie path (browser SPA after POST /login)
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME, "").strip()
    if cookie_val and secrets.compare_digest(cookie_val, expected):
        return cookie_val

    # Neither matched
    if not auth and not cookie_val:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="missing credential (bearer header or session cookie)")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                        detail="invalid credential")


# Convenience for routers
require_token_dep = Depends(require_token)
