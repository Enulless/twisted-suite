"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from twisted.core.db import init_schema, make_engine, make_session_factory
from twisted.core.settings import Settings, reset_settings


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
