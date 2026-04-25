"""Phase 8 legacy-UI guard rails.

Three behaviours are toggled by ``Settings.legacy_ui``:

- ``enabled``  → legacy /dashboard/* renders unchanged.
- ``banner``   → legacy renders WITH a deprecation banner pointing at
                 the equivalent SPA route. Default.
- ``disabled`` → every /dashboard/* GET returns 307 redirect to the
                 SPA equivalent; POST + the auth/redact endpoints
                 still work so the SPA + workers don't break.

The helper here also computes the SPA equivalent for any /dashboard/*
URL so the banner has a "Switch to the new UI →" link that lands on
the right page.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from ..core.settings import get_settings

LegacyMode = Literal["enabled", "banner", "disabled"]


# ──────────────────────────── URL mapping ────────────────────────────


# Each entry: (compiled regex on the legacy path, function returning the
# SPA equivalent path). First match wins.
_MAPPINGS: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
    # Engagement sub-pages (most-specific first)
    (re.compile(r"^/dashboard/engagements/(\d+)/findings/(\d+)/redact/?$"),
     lambda m: f"/engagements/{m.group(1)}/findings/{m.group(2)}"),
    (re.compile(r"^/dashboard/engagements/(\d+)/findings/(\d+)/?$"),
     lambda m: f"/engagements/{m.group(1)}/findings/{m.group(2)}"),
    (re.compile(r"^/dashboard/engagements/(\d+)/findings/?$"),
     lambda m: f"/engagements/{m.group(1)}/findings"),
    (re.compile(r"^/dashboard/engagements/(\d+)/assets/?$"),
     lambda m: f"/engagements/{m.group(1)}/assets"),
    (re.compile(r"^/dashboard/engagements/(\d+)/runs/?$"),
     lambda m: f"/engagements/{m.group(1)}/runs"),
    (re.compile(r"^/dashboard/engagements/(\d+)/?$"),
     lambda m: f"/engagements/{m.group(1)}"),
    # Top-level dashboard pages
    (re.compile(r"^/dashboard/training/([^/]+)/?$"),
     lambda m: "/training"),  # SPA training detail isn't a per-step page yet
    (re.compile(r"^/dashboard/training/?$"),
     lambda _m: "/training"),
    (re.compile(r"^/dashboard/labs(?:/.*)?$"),
     lambda _m: "/labs"),
    (re.compile(r"^/dashboard/workers/?$"),
     lambda _m: "/workers"),
    (re.compile(r"^/dashboard/procedures/?$"),
     lambda _m: "/procedures"),
    (re.compile(r"^/dashboard/?$"),
     lambda _m: "/"),
]


def spa_equivalent(legacy_path: str) -> str:
    """Best-effort SPA path for a given /dashboard/* URL. Falls back
    to '/' (engagement list home) if no mapping matches."""
    for pattern, mapper in _MAPPINGS:
        m = pattern.match(legacy_path)
        if m:
            return mapper(m)
    return "/"


def current_mode() -> LegacyMode:
    s = get_settings()
    val = (getattr(s, "legacy_ui", None) or "banner").lower()
    if val not in ("enabled", "banner", "disabled"):
        return "banner"
    return val  # type: ignore[return-value]


# ──────────────────────────── Middleware-style gate ────────────────────────────


def gate_legacy_get(request: Request) -> None:
    """Dependency for legacy GET handlers. In ``disabled`` mode, raise
    a 307 to the SPA equivalent. In other modes do nothing.

    POST handlers (login, logout, finalize fragments, redact, cvss,
    practice, lab up/down, htmx polling) intentionally bypass this
    gate so the SPA can still consume them while the legacy pages
    are off-limits to humans.
    """
    if current_mode() != "disabled":
        return
    target = spa_equivalent(request.url.path)
    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        detail=f"legacy dashboard disabled; use {target}",
        headers={"Location": target},
    )


def make_redirect_response(legacy_path: str) -> RedirectResponse:
    """Used by tests to build the same redirect the gate would emit."""
    return RedirectResponse(
        url=spa_equivalent(legacy_path),
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )
