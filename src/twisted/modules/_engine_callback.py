"""Helper for modules that need to read back engagement state from the engine."""

from __future__ import annotations

from ..client.api import EngineClient
from ..core.settings import get_settings


def get_client() -> EngineClient:
    """Build an EngineClient using the worker's environment."""
    return EngineClient(settings=get_settings())
