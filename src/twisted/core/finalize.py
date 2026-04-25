"""OneDrive finalize flow.

Promotes hot-side artifacts into the cold-side OneDrive archive when
the operator marks an item as final. Two flows:

- ``finalize_finding(finding, paths_for_evidence)`` copies the
  finding's evidence (preferring redacted_path when set) into
  ``<archive>/engagements/<client>/evidence/finalized/<finding_id>/``.
  The Evidence row's ``finalized_at`` gets stamped.

- ``finalize_report(client, src_paths)`` copies the report file(s)
  into ``<archive>/engagements/<client>/reports/`` and returns the
  written paths.

Both are no-ops (with a structured "not configured" result) if
``Settings.archive_root`` is unset.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .paths import to_canonical
from .settings import Settings, get_settings
from .storage import ArchivePaths, finalize_evidence


@dataclass
class FinalizeResult:
    success: bool
    archived_paths: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    error: str | None = None


def archive_paths_for(client: str, settings: Settings | None = None
                      ) -> ArchivePaths | None:
    s = settings or get_settings()
    if s.archive_root is None:
        return None
    paths = ArchivePaths.for_engagement(client, s)
    if paths is None:
        return None
    return paths.ensure()


def finalize_report(client: str, src_paths: Iterable[Path],
                    settings: Settings | None = None) -> FinalizeResult:
    """Copy report files into ``archive/.../reports/``."""
    archive = archive_paths_for(client, settings)
    if archive is None:
        return FinalizeResult(
            success=False,
            error="archive_root is not configured (set TWISTED_ARCHIVE_ROOT)",
        )
    written: list[str] = []
    skipped: list[str] = []
    for src in src_paths:
        p = Path(src)
        if not p.exists():
            skipped.append(str(p))
            continue
        target = finalize_evidence(p, archive.reports)
        written.append(to_canonical(target))
    return FinalizeResult(success=True, archived_paths=written, skipped=skipped)


def finalize_evidence_for_finding(client: str, finding_id: int,
                                   evidence_rows: list[dict],
                                   settings: Settings | None = None
                                   ) -> FinalizeResult:
    """Copy each row's redacted_path (preferred) or path into the
    archive's per-finding folder.

    ``evidence_rows`` is a list of dicts with keys ``id``, ``path``,
    ``redacted_path`` (optional). The caller is responsible for
    stamping ``finalized_at`` on the ORM rows after this returns.
    """
    archive = archive_paths_for(client, settings)
    if archive is None:
        return FinalizeResult(
            success=False,
            error="archive_root is not configured (set TWISTED_ARCHIVE_ROOT)",
        )
    target_dir = archive.evidence / str(finding_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skipped: list[str] = []
    for row in evidence_rows:
        # Prefer redacted version when available — that's the whole
        # point of the redaction flow.
        src_str = row.get("redacted_path") or row.get("path")
        if not src_str:
            skipped.append(f"<no path on row id={row.get('id')}>")
            continue
        p = Path(src_str)
        if not p.exists():
            skipped.append(str(p))
            continue
        target = finalize_evidence(p, target_dir)
        written.append(to_canonical(target))
    return FinalizeResult(success=True, archived_paths=written, skipped=skipped)


def now_utc() -> datetime:
    return datetime.now(UTC)
