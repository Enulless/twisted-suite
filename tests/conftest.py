"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from twisted.core.db import init_schema, make_engine, make_session_factory
from twisted.core.settings import Settings, reset_settings


class ApiClient:
    """Thin wrapper around ``TestClient`` that prefixes every JSON-API
    path with ``/api`` so test bodies can keep using bare paths.

    Phase 8A moved every JSON router under ``/api/*``; tests written
    before that just call ``client.get('/engagements')`` etc. This
    wrapper preserves that ergonomics without rewriting every call site.

    Paths starting with ``/api``, ``/dashboard``, ``/static``, ``/login``,
    ``/logout``, or ``/htmx`` are passed through unchanged so dashboard
    tests still work.
    """

    _PASSTHROUGH = ("/api", "/dashboard", "/static", "/login",
                    "/logout", "/htmx")

    def __init__(self, client: TestClient) -> None:
        self._inner = client

    def _adjust(self, path: str) -> str:
        if any(path.startswith(p) for p in self._PASSTHROUGH):
            return path
        if path.startswith("/"):
            return "/api" + path
        return path

    def get(self, path: str, **kw: Any) -> Any:  # noqa: ANN401
        return self._inner.get(self._adjust(path), **kw)

    def post(self, path: str, **kw: Any) -> Any:  # noqa: ANN401
        return self._inner.post(self._adjust(path), **kw)

    def put(self, path: str, **kw: Any) -> Any:  # noqa: ANN401
        return self._inner.put(self._adjust(path), **kw)

    def delete(self, path: str, **kw: Any) -> Any:  # noqa: ANN401
        return self._inner.delete(self._adjust(path), **kw)

    def patch(self, path: str, **kw: Any) -> Any:  # noqa: ANN401
        return self._inner.patch(self._adjust(path), **kw)

    @property
    def app(self) -> Any:  # noqa: ANN401
        return self._inner.app

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        return getattr(self._inner, name)


@pytest.fixture
def tmp_data_root(tmp_path: Path) -> Iterator[Path]:
    """Isolated data root for tests. Auto-cleaned by tmp_path."""
    root = tmp_path / "twisted_data"
    root.mkdir()
    (root / "engagements").mkdir()
    (root / "workers").mkdir()
    yield root


@pytest.fixture
def isolated_settings(tmp_data_root: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Replace global Settings with one rooted in tmp_data_root."""
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_data_root))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_data_root / "worker.token"))
    monkeypatch.setenv("TWISTED_DB_URL", f"sqlite:///{tmp_data_root}/twisted.db")
    s = Settings()
    s.ensure_dirs()
    reset_settings(s)
    try:
        yield s
    finally:
        reset_settings(None)


@pytest.fixture
def engine_in_memory() -> Iterator[Engine]:
    """A fresh in-memory SQLite engine with the full schema applied."""
    engine = make_engine(url="sqlite:///:memory:")
    init_schema(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def session_factory(engine_in_memory: Engine) -> sessionmaker[Session]:
    return make_session_factory(engine_in_memory)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    s = session_factory()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def file_engine(tmp_data_root: Path) -> Iterator[Engine]:
    """File-backed SQLite engine (exercises pragmas + WAL mode)."""
    db = tmp_data_root / "twisted.db"
    engine = make_engine(url=f"sqlite:///{db}")
    init_schema(engine)
    try:
        yield engine
    finally:
        engine.dispose()
