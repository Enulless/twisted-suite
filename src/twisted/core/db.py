"""SQLite engine + session management.

Single writer model: only the engine process should construct an Engine that
points at the canonical ``twisted.db`` file. Workers and the CLI go through
the engine's HTTP API instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .models import Base
from .settings import get_settings


def _enable_sqlite_pragmas(dbapi_connection, connection_record) -> None:  # noqa: ANN001 - SA hook
    """SQLite tuning suitable for single-writer + many-reader workloads."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.execute("PRAGMA synchronous = NORMAL")
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("PRAGMA temp_store = MEMORY")
    cursor.execute("PRAGMA busy_timeout = 5000")
    cursor.close()


def make_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy Engine pointed at the engine SQLite file.

    Parameters
    ----------
    url
        Override the URL (used by tests with ``sqlite:///:memory:`` or a
        temp file). When None, falls back to ``settings.db_url``.
    echo
        Echo SQL to stdout for debugging.
    """
    settings = get_settings()
    target_url = url or settings.db_url

    # SQLite-specific connect args: allow cross-thread use (FastAPI workers
    # and tests both need it). For file URLs ensure parent dir exists.
    connect_args: dict = {}
    if target_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if "///" in target_url and ":memory:" not in target_url:
            db_path = Path(target_url.split("///", 1)[1])
            db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(target_url, echo=echo, future=True, connect_args=connect_args)
    if target_url.startswith("sqlite"):
        event.listen(engine, "connect", _enable_sqlite_pragmas)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_schema(engine: Engine) -> None:
    """Create all tables. Idempotent."""
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield a session, commit on success, rollback on failure, always close."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
