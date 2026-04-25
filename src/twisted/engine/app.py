"""FastAPI application factory for the Twisted engine."""

from __future__ import annotations

import importlib.resources as resources
from collections.abc import Iterable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..core.db import init_schema, make_engine, make_session_factory
from ..core.procedures import ProcedureLoader
from ..core.settings import Settings, get_settings
from .auth import ensure_token
from .routes import assets as assets_router
from .routes import engagements as engagements_router
from .routes import finalize as finalize_router
from .routes import findings as findings_router
from .routes import jobs as jobs_router
from .routes import labs as labs_router
from .routes import system as system_router
from .routes import tool_policy as tool_policy_router
from .routes import training as training_router
from .routes import web as web_router
from .routes import workers as workers_router
from .state import EngineState


def _web_paths() -> tuple[Path, Path]:
    """Resolve template + static directories from the installed package."""
    web_root = Path(str(resources.files("twisted.web")))
    return web_root / "templates", web_root / "static"


def _spa_dist_dir() -> Path | None:
    """Locate the built SPA bundle.

    Searches the conventional ``frontend/dist`` next to the project
    root. Returns ``None`` if the SPA hasn't been built yet — in that
    case the legacy ``/dashboard/*`` Jinja templates remain the user
    interface (Phase 8C deletes them once the SPA is the default).
    """
    # ``app.py`` lives at src/twisted/engine/app.py — go up four levels
    # to reach the repo root, then look for frontend/dist.
    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    candidate = repo_root / "frontend" / "dist"
    return candidate if candidate.is_file() or candidate.is_dir() else None


def _build_state(settings: Settings,
                 procedure_search_paths: Iterable[Path | str] | None) -> EngineState:
    settings.ensure_dirs()
    db_engine = make_engine()
    init_schema(db_engine)
    factory = make_session_factory(db_engine)
    procs = ProcedureLoader(search_paths=procedure_search_paths)
    procs.all()  # eager-load so config errors surface at startup
    return EngineState(db_engine=db_engine, session_factory=factory, procedures=procs)


def create_app(*, settings: Settings | None = None,
               procedure_search_paths: Iterable[Path | str] | None = None) -> FastAPI:
    """Create a FastAPI app bound to the given settings.

    A fresh app is created per call (used by tests). The engine token is
    auto-created on first call.
    """
    s = settings or get_settings()
    ensure_token(s)
    state = _build_state(s, procedure_search_paths)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ARG001 - signature required
        yield
        state.db_engine.dispose()

    app = FastAPI(
        title="Twisted Pen Testing Suite — Engine",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.engine_state = state
    app.state.settings = s

    # JSON API mounted under /api/* so the SPA can own bare paths
    # (/, /engagements/:id, /workers, ...) without shadowing JSON routes.
    api_prefix = "/api"
    app.include_router(system_router.router, prefix=api_prefix)
    app.include_router(workers_router.router, prefix=api_prefix)
    app.include_router(engagements_router.router, prefix=api_prefix)
    app.include_router(assets_router.router, prefix=api_prefix)
    app.include_router(findings_router.router, prefix=api_prefix)
    app.include_router(jobs_router.router, prefix=api_prefix)
    app.include_router(training_router.router, prefix=api_prefix)
    app.include_router(labs_router.router, prefix=api_prefix)
    app.include_router(finalize_router.router, prefix=api_prefix)
    app.include_router(tool_policy_router.router, prefix=api_prefix)

    # Browser dashboard (Phase 5): Jinja2 + HTMX, cookie-auth on top of
    # the same bearer token. Static assets at /static/, login at /login,
    # all dashboard pages mounted at /, /workers, /procedures,
    # /engagements/... — see engine.routes.web for the full surface.
    template_dir, static_dir = _web_paths()
    if template_dir.is_dir():
        templates = Jinja2Templates(directory=str(template_dir))
        web_router.configure_templates(templates)
        app.include_router(web_router.router)
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Phase 8: serve the Vite SPA from frontend/dist when present.
    # Mounting last so the JSON API (/api/*), legacy dashboard
    # (/dashboard/*), /login, /logout, and /static all win over the
    # SPA's catch-all. The SPA owns /, /engagements/:id, /workers,
    # /labs, /training, /procedures (root-level, not /dashboard/*).
    spa_dist = _spa_dist_dir()
    if spa_dist and spa_dist.is_dir():
        # html=True makes StaticFiles fall back to index.html for any
        # unknown path, which is exactly what a client-side router needs.
        app.mount("/", StaticFiles(directory=str(spa_dist), html=True),
                  name="spa")
    else:
        # No SPA built — root URL redirects to the legacy /dashboard/.
        from fastapi.responses import RedirectResponse
        @app.get("/", include_in_schema=False)
        def _root_redirect() -> RedirectResponse:
            return web_router.make_root_redirect_to_dashboard()

    return app
