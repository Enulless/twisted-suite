"""Runtime settings for engine, workers, and CLI.

All paths and connection details flow through one Settings object so tests can
override them via environment variables or by constructing a Settings() with
explicit overrides.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_root() -> Path:
    """Hot/transient data root.

    Defaults to ~/twisted/data on the engine host. Workers running on Windows
    will translate this path into the WSL form when reading/writing across
    the boundary (see core.paths).
    """
    return Path(os.environ.get("TWISTED_DATA_ROOT", str(Path.home() / "twisted" / "data")))


def _default_archive_root() -> Path | None:
    """Cold/finalized data root (OneDrive folder by default).

    None disables the finalize step (useful in tests).
    """
    raw = os.environ.get("TWISTED_ARCHIVE_ROOT")
    if raw is None:
        # Best-effort default: the user's existing OneDrive Twisted folder.
        candidate = Path("/mnt/c/Users/awhwt/OneDrive/Desktop/Twisted/data")
        return candidate if candidate.parent.exists() else None
    return Path(raw) if raw else None


def _default_token_file() -> Path:
    return Path(os.environ.get("TWISTED_TOKEN_FILE", str(Path.home() / ".twisted" / "worker.token")))


class Settings(BaseSettings):
    """Centralised configuration."""

    model_config = SettingsConfigDict(
        env_prefix="TWISTED_",
        env_file=None,
        extra="ignore",
    )

    # Engine bind address
    engine_host: str = "127.0.0.1"
    engine_port: int = 8000

    # URL the worker / CLI use to reach the engine
    engine_url: str = "http://127.0.0.1:8000"

    # Filesystem layout
    data_root: Path = Field(default_factory=_default_data_root)
    archive_root: Path | None = Field(default_factory=_default_archive_root)

    # Auth
    token_file: Path = Field(default_factory=_default_token_file)

    # Worker tunables
    worker_poll_interval: float = 2.0  # seconds between job-poll attempts when idle
    worker_heartbeat_interval: float = 15.0
    job_claim_timeout: int = 30  # seconds before a stalled claim is reclaimable

    @field_validator("archive_root", mode="before")
    @classmethod
    def _empty_archive_means_disabled(cls, v: object) -> object:
        if v in ("", None):
            return None
        return v

    @property
    def db_url(self) -> str:
        """SQLite URL for the engine. Always file-backed under data_root."""
        url = os.environ.get("TWISTED_DB_URL")
        if url:
            return url
        return f"sqlite:///{self.data_root / 'twisted.db'}"

    @property
    def engagements_dir(self) -> Path:
        return self.data_root / "engagements"

    @property
    def workers_log_dir(self) -> Path:
        return self.data_root / "workers"

    def ensure_dirs(self) -> None:
        """Create all required hot-data directories. Safe to call repeatedly."""
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.engagements_dir.mkdir(parents=True, exist_ok=True)
        self.workers_log_dir.mkdir(parents=True, exist_ok=True)
        self.token_file.parent.mkdir(parents=True, exist_ok=True)


# Module-level cached instance. Tests can call get_settings.cache_clear()
# (after wrapping in lru_cache) or simply construct Settings() directly.
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings(new: Settings | None = None) -> None:
    """Replace the cached Settings (used by tests)."""
    global _settings
    _settings = new
