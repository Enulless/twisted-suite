"""SQLAlchemy ORM models for the engagement store.

Single-writer SQLite owned by the engine process. All other components
(workers, CLI, dashboard) interact with this data exclusively through the
HTTP API the engine exposes.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Common base for all ORM models."""


# ──────────────────────────── Enums ────────────────────────────


class EngagementStatus(enum.StrEnum):
    PLANNING = "planning"
    ACTIVE = "active"
    REPORTING = "reporting"
    CLOSED = "closed"


class ScopeKind(enum.StrEnum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    OOS = "oos"


class StepMode(enum.StrEnum):
    AUTO = "auto"
    WALKTHROUGH = "walkthrough"
    HYBRID = "hybrid"


class StepStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class JobState(enum.StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class JobRuntime(enum.StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    EITHER = "either"


class WorkerStatus(enum.StrEnum):
    ONLINE = "online"
    BUSY = "busy"
    OFFLINE = "offline"


class FindingSeverity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(enum.StrEnum):
    DRAFT = "draft"
    NEEDS_VERIFICATION = "needs_verification"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    REMEDIATED = "remediated"


class EvidenceKind(enum.StrEnum):
    SCREENSHOT = "screenshot"
    HTTP_REQRES = "http_reqres"
    COMMAND_OUTPUT = "command_output"
    PCAP = "pcap"
    VIDEO = "video"
    FILE = "file"
    NOTE = "note"


class ToolPolicyKind(enum.StrEnum):
    """What a tool-policy row targets."""
    STEP = "step"            # individual procedure step id (e.g. bb.stage4.nmap_full)
    CAPABILITY = "capability"  # capability tag (e.g. wrk, monitor-mode)


# ──────────────────────────── Tables ────────────────────────────


class Engagement(Base):
    __tablename__ = "engagement"

    id: Mapped[int] = mapped_column(primary_key=True)
    client: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    primary_domain: Mapped[str | None] = mapped_column(String(255))
    scope_doc_path: Mapped[str | None] = mapped_column(String(1024))
    root_dir: Mapped[str | None] = mapped_column(String(1024))
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus), default=EngagementStatus.PLANNING
    )
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    step_runs: Mapped[list[StepRun]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    tool_policy: Mapped[list[EngagementToolPolicy]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class ScopeRule(Base):
    __tablename__ = "scope_rule"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id"), index=True)
    kind: Mapped[ScopeKind] = mapped_column(Enum(ScopeKind))
    pattern: Mapped[str] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)

    engagement: Mapped[Engagement] = relationship(back_populates="scope_rules")


class Asset(Base):
    """The 'master spreadsheet' row."""

    __tablename__ = "asset"
    __table_args__ = (UniqueConstraint("engagement_id", "host", name="uq_asset_eng_host"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id"), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    env_type: Mapped[str | None] = mapped_column(String(40))  # production / staging / dev / unknown
    source: Mapped[str | None] = mapped_column(String(120))  # crt.sh / sublist3r / etc
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_total: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text)
    extra: Mapped[dict | None] = mapped_column(JSON)

    engagement: Mapped[Engagement] = relationship(back_populates="assets")
    ports: Mapped[list[Port]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    techs: Mapped[list[Technology]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    cves: Mapped[list[CVE]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    risk_scores: Mapped[list[RiskScore]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "port"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "proto", name="uq_port_asset_port_proto"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(120))
    banner: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    asset: Mapped[Asset] = relationship(back_populates="ports")


class Technology(Base):
    __tablename__ = "technology"
    __table_args__ = (UniqueConstraint("asset_id", "name", name="uq_tech_asset_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(64))
    category: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(String(64))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    asset: Mapped[Asset] = relationship(back_populates="techs")


class CVE(Base):
    __tablename__ = "cve"
    __table_args__ = (UniqueConstraint("asset_id", "cve_id", name="uq_cve_asset"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str] | None] = mapped_column(JSON)

    asset: Mapped[Asset] = relationship(back_populates="cves")


class RiskScore(Base):
    """One row per scoring factor per asset (matches the bug-bounty matrix)."""

    __tablename__ = "risk_score"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    factor: Mapped[str] = mapped_column(String(80))
    points: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str | None] = mapped_column(Text)

    asset: Mapped[Asset] = relationship(back_populates="risk_scores")


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("asset.id"))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity), default=FindingSeverity.INFO
    )
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(120))
    cwe: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.DRAFT
    )
    description: Mapped[str | None] = mapped_column(Text)
    root_cause: Mapped[str | None] = mapped_column(Text)
    affected_component: Mapped[str | None] = mapped_column(Text)
    repro_steps: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    engagement: Mapped[Engagement] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("finding.id"), index=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id"), index=True)
    kind: Mapped[EvidenceKind] = mapped_column(Enum(EvidenceKind))
    path: Mapped[str] = mapped_column(String(1024))  # canonical (POSIX/WSL) form
    redacted_path: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    captured_by_worker: Mapped[str | None] = mapped_column(String(120))
    host: Mapped[str | None] = mapped_column(String(16))  # 'wsl' | 'windows'
    note: Mapped[str | None] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding | None] = relationship(back_populates="evidence")
    engagement: Mapped[Engagement] = relationship()


class StepRun(Base):
    __tablename__ = "step_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id"), index=True)
    procedure: Mapped[str] = mapped_column(String(40))  # bb / wp_stress / wifi
    stage: Mapped[str | None] = mapped_column(String(40))
    step_id: Mapped[str] = mapped_column(String(120), index=True)  # e.g. bb.stage1.crtsh
    mode: Mapped[StepMode] = mapped_column(Enum(StepMode), default=StepMode.AUTO)
    status: Mapped[StepStatus] = mapped_column(Enum(StepStatus), default=StepStatus.PENDING)
    params: Mapped[dict | None] = mapped_column(JSON)
    artifact_paths: Mapped[list[str] | None] = mapped_column(JSON)
    output_summary: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(120))

    engagement: Mapped[Engagement] = relationship(back_populates="step_runs")
    job: Mapped[Job | None] = relationship(back_populates="step_run", uselist=False)


class Worker(Base):
    __tablename__ = "worker"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120))
    os: Mapped[str] = mapped_column(String(40))  # linux / windows / wsl
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str] | None] = mapped_column(JSON)
    status: Mapped[WorkerStatus] = mapped_column(
        Enum(WorkerStatus), default=WorkerStatus.ONLINE
    )
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    version: Mapped[str | None] = mapped_column(String(40))


class Job(Base):
    __tablename__ = "job"

    id: Mapped[int] = mapped_column(primary_key=True)
    step_run_id: Mapped[int] = mapped_column(ForeignKey("step_run.id"), unique=True, index=True)
    runtime: Mapped[JobRuntime] = mapped_column(Enum(JobRuntime), default=JobRuntime.EITHER)
    requires: Mapped[list[str] | None] = mapped_column(JSON)
    state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.PENDING, index=True)
    claimed_by: Mapped[str | None] = mapped_column(String(120), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict | None] = mapped_column(JSON)

    step_run: Mapped[StepRun] = relationship(back_populates="job")


class EngagementToolPolicy(Base):
    """Per-engagement RoE tool policy.

    One row per (engagement, target_kind, target_value). ``target_kind``
    is either ``step`` (the row gates a specific procedure step id) or
    ``capability`` (the row gates a capability tag — blocking it
    cascades to disable every step that ``requires:`` it).

    Default semantics: a step is allowed unless an explicit row with
    ``allowed=False`` matches it (directly by step_id, or indirectly
    via a required capability).
    """

    __tablename__ = "engagement_tool_policy"
    __table_args__ = (
        UniqueConstraint("engagement_id", "target_kind", "target_value",
                         name="uq_tool_policy_eng_kind_target"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagement.id"), index=True
    )
    target_kind: Mapped[ToolPolicyKind] = mapped_column(Enum(ToolPolicyKind))
    target_value: Mapped[str] = mapped_column(String(120), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    engagement: Mapped[Engagement] = relationship(back_populates="tool_policy")


class TrainingProgress(Base):
    __tablename__ = "training_progress"
    __table_args__ = (
        UniqueConstraint("user", "lesson_id", "quiz_id", name="uq_training_user_lesson_quiz"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user: Mapped[str] = mapped_column(String(120), index=True)
    lesson_id: Mapped[str | None] = mapped_column(String(120))
    quiz_id: Mapped[str | None] = mapped_column(String(120))
    score: Mapped[float | None] = mapped_column(Float)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    notes: Mapped[str | None] = mapped_column(Text)


__all__ = [
    "Asset",
    "Base",
    "CVE",
    "Engagement",
    "EngagementStatus",
    "EngagementToolPolicy",
    "Evidence",
    "EvidenceKind",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "Job",
    "JobRuntime",
    "JobState",
    "Port",
    "RiskScore",
    "ScopeKind",
    "ScopeRule",
    "StepMode",
    "StepRun",
    "StepStatus",
    "Technology",
    "ToolPolicyKind",
    "TrainingProgress",
    "Worker",
    "WorkerStatus",
]
