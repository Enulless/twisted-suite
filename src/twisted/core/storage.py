"""Engagement storage layout.

Two roots:

- *hot* (``Settings.data_root``): SQLite + per-step artifacts + raw evidence.
  Lives on WSL native FS for speed and to avoid OneDrive sync interference.
- *cold* (``Settings.archive_root``, optional): finalized reports and
  PII-redacted evidence pushed to OneDrive on ``twisted finalize``.

Folder layout under hot per engagement (mirrors the procedure docs)::

    engagements/<client>/
      raw/<stage-folder>/<step>_<timestamp>.{txt,json}
      captures/                    # pcaps, hashcat work, large wordlists
      evidence/raw/                # original screenshots / video
      logs/                        # per-step run logs

Cold layout under archive::

    engagements/<client>/
      reports/                     # html / pdf
      evidence/finalized/<finding-id>/
      master_spreadsheet.xlsx
      roe.md
      summary.md
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .paths import to_canonical
from .settings import Settings, get_settings

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def slugify(name: str, *, max_len: int = 80) -> str:
    """Filesystem-safe slug for engagement / step / finding names."""
    s = _SLUG_RE.sub("_", name.strip().lower()).strip("_-.")
    return s[:max_len] or "unnamed"


def stage_folder(stage: str | None) -> str:
    """Convert a stage identifier into a procedure-doc-style folder name."""
    if not stage:
        return "misc"
    s = re.sub(r"[^a-z0-9]+", "-", str(stage).lower()).strip("-")
    return s or "misc"


@dataclass
class EngagementPaths:
    """Resolved paths for a single engagement, hot side only."""

    client: str
    root: Path
    raw: Path
    captures: Path
    evidence_raw: Path
    logs: Path

    @classmethod
    def for_engagement(
        cls, client: str, settings: Settings | None = None
    ) -> EngagementPaths:
        s = settings or get_settings()
        slug = slugify(client)
        root = s.engagements_dir / slug
        return cls(
            client=client,
            root=root,
            raw=root / "raw",
            captures=root / "captures",
            evidence_raw=root / "evidence" / "raw",
            logs=root / "logs",
        )

    def ensure(self) -> EngagementPaths:
        for p in (self.root, self.raw, self.captures, self.evidence_raw, self.logs):
            p.mkdir(parents=True, exist_ok=True)
        return self

    def step_dir(self, stage: str | None) -> Path:
        d = self.raw / stage_folder(stage)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def step_artifact(
        self,
        stage: str | None,
        step_id: str,
        ext: str = "txt",
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        ts = (timestamp or datetime.now()).strftime("%Y%m%d_%H%M%S")
        slug = slugify(step_id.replace(".", "_"))
        return self.step_dir(stage) / f"{slug}_{ts}.{ext.lstrip('.')}"


@dataclass
class ArchivePaths:
    """Resolved paths for a single engagement on the cold (OneDrive) side."""

    client: str
    root: Path
    reports: Path
    evidence: Path

    @classmethod
    def for_engagement(
        cls, client: str, settings: Settings | None = None
    ) -> ArchivePaths | None:
        s = settings or get_settings()
        if not s.archive_root:
            return None
        slug = slugify(client)
        root = s.archive_root / "engagements" / slug
        return cls(
            client=client,
            root=root,
            reports=root / "reports",
            evidence=root / "evidence" / "finalized",
        )

    def ensure(self) -> ArchivePaths:
        for p in (self.root, self.reports, self.evidence):
            p.mkdir(parents=True, exist_ok=True)
        return self


def write_artifact(path: Path, content: str | bytes) -> Path:
    """Write artifact content, creating parent dirs. Returns canonical path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_bytes(content)
    return Path(to_canonical(path))


def finalize_evidence(src: Path, dest_dir: Path) -> Path:
    """Copy redacted evidence to the cold archive. Returns the archive path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / src.name
    shutil.copy2(src, target)
    return target
