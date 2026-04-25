"""Pydantic schemas for the engine HTTP API.

Kept deliberately separate from ``core.models`` (SQLAlchemy ORM): API
contracts and DB shape can evolve independently. Workers, CLI, and
dashboard all consume these schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ──────────────────────────── Workers ────────────────────────────


class WorkerRegister(BaseModel):
    id: str
    hostname: str
    os: str  # linux | windows | wsl
    capabilities: list[str] = Field(default_factory=list)
    tags: list[str] | None = None
    version: str | None = None


class WorkerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    os: str
    capabilities: list[str]
    tags: list[str] | None = None
    status: str
    registered_at: datetime
    last_seen: datetime
    version: str | None = None


# ──────────────────────────── Engagements ────────────────────────────


class EngagementCreate(BaseModel):
    client: str
    primary_domain: str | None = None
    notes: str | None = None
    scope: list[dict[str, str]] = Field(default_factory=list)
    # scope items: [{"kind": "exact", "pattern": "api.foo.com"}, ...]


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client: str
    primary_domain: str | None
    status: str
    root_dir: str | None
    created_at: datetime


# ──────────────────────────── Assets ────────────────────────────


class AssetUpsert(BaseModel):
    host: str
    ip: str | None = None
    env_type: str | None = None
    source: str | None = None
    in_scope: bool | None = None
    extra: dict[str, Any] | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    host: str
    ip: str | None
    env_type: str | None
    source: str | None
    in_scope: bool
    risk_total: int
    discovered_at: datetime
    last_seen: datetime


# ──────────────────────────── Findings ────────────────────────────


class FindingDraftIn(BaseModel):
    title: str
    severity: str = "info"
    cwe: str | None = None
    affected_component: str | None = None
    description: str | None = None
    repro_steps: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    asset_host: str | None = None  # link to asset by host name (looked up server-side)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    title: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    cwe: str | None
    status: str


# ──────────────────────────── Step runs / jobs ────────────────────────────


class StepRunRequest(BaseModel):
    engagement_id: int
    step_id: str
    params: dict[str, Any] = Field(default_factory=dict)


class StepRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    procedure: str
    stage: str | None
    step_id: str
    mode: str
    status: str
    started_at: datetime | None
    ended_at: datetime | None
    worker_id: str | None
    output_summary: str | None


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    step_run_id: int
    runtime: str
    requires: list[str] | None
    state: str
    claimed_by: str | None


class JobOffer(BaseModel):
    """The payload an engine returns to a worker that has claimed a job."""

    job_id: int
    step_run_id: int
    engagement_id: int
    procedure: str
    stage: str | None
    step_id: str
    module: str | None
    params: dict[str, Any]
    work_dir: str  # canonical path on the worker host (engine resolves on its side)


class EvidenceIn(BaseModel):
    path: str
    kind: str = "command_output"
    note: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    host: str | None = None


class JobResult(BaseModel):
    success: bool
    summary: str | None = None
    error: str | None = None
    artifact_paths: list[str] = Field(default_factory=list)
    assets: list[AssetUpsert] = Field(default_factory=list)
    findings: list[FindingDraftIn] = Field(default_factory=list)
    evidence: list[EvidenceIn] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────── Procedure metadata ────────────────────────────


class ProcedureSummary(BaseModel):
    id: str
    name: str
    description: str | None
    stages: list[dict[str, Any]]
