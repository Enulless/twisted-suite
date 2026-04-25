"""Engine application state.

Holds the SQLAlchemy engine, session factory, the procedure loader,
and the lesson/quiz repos in one place so FastAPI dependencies can
resolve them. We avoid module-level globals; ``state.py`` lives in
``app.state`` after construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ..core.procedures import ProcedureLoader
from ..training import LessonRepo, QuizRepo


@dataclass
class EngineState:
    db_engine: Engine
    session_factory: sessionmaker
    procedures: ProcedureLoader
    lesson_repo: LessonRepo | None = None
    quiz_repo: QuizRepo | None = None
