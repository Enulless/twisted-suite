"""FastAPI application factory for the Twisted engine."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

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
from .routes import workers as workers_router
from .state import EngineState


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

    return app
