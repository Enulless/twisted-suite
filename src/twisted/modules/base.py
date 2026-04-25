"""Shared module contract.

Every automated step module exports a callable (typically named ``run``) that
accepts a ``ModuleContext`` and returns a ``ModuleResult``. The worker
discovers modules via the ``module: pkg.mod:callable`` field in the
procedure YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AssetUpdate:
    """An asset/host the module discovered or refined.

    Used by the engine to upsert into the master spreadsheet.
    """

    host: str
    ip: str | None = None
    env_type: str | None = None
    source: str | None = None
    in_scope: bool | None = None
    extra: dict[str, Any] | None = None


@dataclass
class FindingDraft:
    """A draft finding the module wants the operator to review."""

    title: str
    severity: str = "info"
    cwe: str | None = None
    affected_component: str | None = None
    description: str | None = None
    repro_steps: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    extra: dict[str, Any] | None = None


@dataclass
class EvidenceRef:
    """A path on the worker host that should be ingested as evidence."""

    path: str  # canonical (POSIX/WSL) form
    kind: str = "command_output"
    note: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    host: str | None = None  # 'wsl' | 'windows'


@dataclass
class ModuleResult:
    """Structured return value from a module's ``run``."""

    success: bool = True
    artifacts: list[Path] = field(default_factory=list)
    assets: list[AssetUpdate] = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    summary: str | None = None
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleContext:
    """Per-step execution context handed to the module by the worker."""

    engagement_id: int
    step_id: str
    procedure: str
    stage: str | None
    params: dict[str, Any]
    work_dir: Path  # where to write artifacts
    scope: Any | None = None  # core.scope.Scope instance
    timestamp: datetime = field(default_factory=datetime.now)
    worker_id: str | None = None
    worker_host: str = "wsl"
