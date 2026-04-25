"""Cookie-based session auth for the browser dashboard.

The JSON API still requires ``Authorization: Bearer <token>``; the
dashboard layers a thin cookie session on top so a human in a browser
doesn't have to set request headers manually. The cookie value is the
same bearer token — there's no separate session store, no JWT, no DB
session table. Logout simply clears the cookie.

Auth flow:
  GET  /login           -> render the login form. Pre-fills the token
                           from the local token file when the dashboard
                           is running on the same host as the engine
                           (the common single-user case), so the user
                           usually just clicks "Login".
  POST /login           -> validate the submitted token against the
                           engine's token file, set HttpOnly cookie,
                           redirect to ?next= or /.
  GET  /logout          -> clear the cookie, redirect to /login.

Dashboard route handlers depend on ``require_dashboard_session``, which
accepts EITHER:
  - ``Authorization: Bearer <token>`` (so curl / tests still work), OR
  - the ``twisted_token`` cookie set by /login.

If neither is valid the dependency raises a 303 redirect to /login
(preserving the originally requested path in ?next=) instead of a JSON
401, which is what a browser actually wants.
"""

from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from .auth import read_token

COOKIE_NAME = "twisted_token"
# 7 days in seconds. Fine for a single-user localhost dashboard; the
# cookie is HttpOnly + SameSite=Strict so the only way to extract it is
# via filesystem access, which already implies game-over for the host.
COOKIE_MAX_AGE = 7 * 24 * 3600


def _bearer_from_header(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip() or None
    return None


def _token_from_cookie(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME) or None


def is_valid(presented: str | None) -> bool:
    """Constant-time compare against the engine's token file."""
    if not presented:
        return False
    expected = read_token() or ""
    if not expected:
        return False
    return secrets.compare_digest(presented, expected)


def require_dashboard_session(request: Request) -> str:
    """FastAPI dependency: enforce a valid session for dashboard routes.

    Tries the bearer header first, then the session cookie. On failure
    raises a 303 redirect to /login?next=<original path>; FastAPI
    propagates the response correctly when the dependency raises an
    ``HTTPException`` whose detail is a ``RedirectResponse``-equivalent.

    We use HTTPException with status_code=303 and a Location header in
    detail so the browser follows it cleanly.
    """
    presented = _bearer_from_header(request) or _token_from_cookie(request)
    if is_valid(presented):
        return presented or ""
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        detail="login required",
        headers={"Location": f"/login?next={quote(next_path, safe='')}"},
    )


def make_session_cookie_response(target: str, token: str) -> RedirectResponse:
    """Build a redirect response that sets the session cookie."""
    resp = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="strict",
        # The engine binds to 127.0.0.1 by default and is reached over
        # plain HTTP from the local browser — Secure=True would cause
        # the cookie to be dropped. Production deployments behind a
        # TLS-terminating proxy can override via an env var later.
        secure=False,
        path="/",
    )
    return resp


def make_logout_response(target: str = "/login") -> RedirectResponse:
    resp = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(key=COOKIE_NAME, path="/")
    return resp
