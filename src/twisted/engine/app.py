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
from .routes import findings as findings_router
from .routes import jobs as jobs_router
from .routes import system as system_router
from .routes import training as training_router
from .routes import web as web_router
from .routes import workers as workers_router
from .state import EngineState


def _web_paths() -> tuple[Path, Path]:
    """Resolve template + static directories from the installed package."""
    web_root = Path(str(resources.files("twisted.web")))
    return web_root / "templates", web_root / "static"


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

    app.include_router(system_router.router)
    app.include_router(workers_router.router)
    app.include_router(engagements_router.router)
    app.include_router(assets_router.router)
    app.include_router(findings_router.router)
    app.include_router(jobs_router.router)
    app.include_router(training_router.router)

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

    return app
