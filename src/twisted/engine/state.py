"""Engine application state.

Holds the SQLAlchemy engine, session factory, and the procedure loader
in one place so FastAPI dependencies can resolve them. We avoid module-
level globals; ``state.py`` lives in ``app.state`` after construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ..core.procedures import ProcedureLoader


@dataclass
class EngineState:
    db_engine: Engine
    session_factory: sessionmaker
    procedures: ProcedureLoader
