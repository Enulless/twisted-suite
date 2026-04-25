"""Unit tests for OneDrive finalize helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from twisted.core.finalize import (
    archive_paths_for,
    finalize_evidence_for_finding,
    finalize_report,
)
from twisted.core.settings import Settings


@pytest.fixture
def configured_settings(tmp_path: Path,
                          monkeypatch: pytest.MonkeyPatch) -> Settings:
    archive = tmp_path / "archive"
    archive.mkdir()
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", str(archive))
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    s = Settings()
    s.ensure_dirs()
    return s


@pytest.fixture
def disabled_settings(tmp_path: Path,
                       monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("TWISTED_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", "")
    monkeypatch.setenv("TWISTED_TOKEN_FILE", str(tmp_path / "worker.token"))
    s = Settings()
    s.ensure_dirs()
    return s


class TestArchivePaths:
    def test_returns_none_when_archive_unset(self, disabled_settings) -> None:
        assert archive_paths_for("ACME", disabled_settings) is None

    def test_returns_paths_when_configured(self, configured_settings) -> None:
        paths = archive_paths_for("ACME", configured_settings)
        assert paths is not None
        assert paths.reports.is_dir()
        assert paths.evidence.is_dir()


class TestFinalizeReport:
    def test_skips_when_archive_unset(self, disabled_settings,
                                        tmp_path: Path) -> None:
        f = tmp_path / "report.html"
        f.write_text("hi")
        result = finalize_report("ACME", [f], disabled_settings)
        assert result.success is False
        assert "archive_root" in (result.error or "")
        assert result.archived_paths == []

    def test_archives_files(self, configured_settings, tmp_path: Path) -> None:
        f1 = tmp_path / "report.html"
        f2 = tmp_path / "report.pdf"
        f1.write_text("html body")
        f2.write_bytes(b"%PDF-fake")
        result = finalize_report("ACME", [f1, f2], configured_settings)
        assert result.success is True
        assert len(result.archived_paths) == 2
        for p in result.archived_paths:
            assert Path(p).exists()
            assert "engagements/acme/reports/" in str(p)

    def test_skips_missing_files_gracefully(self, configured_settings,
                                              tmp_path: Path) -> None:
        f = tmp_path / "exists.html"
        f.write_text("ok")
        missing = tmp_path / "ghost.pdf"
        result = finalize_report("ACME", [f, missing], configured_settings)
        assert result.success is True
        assert len(result.archived_paths) == 1
        assert str(missing) in result.skipped


class TestFinalizeEvidenceForFinding:
    def test_prefers_redacted_path(self, configured_settings,
                                     tmp_path: Path) -> None:
        original = tmp_path / "shot.png"
        redacted = tmp_path / "redacted_shot.png"
        original.write_bytes(b"original")
        redacted.write_bytes(b"redacted-pngdata")
        result = finalize_evidence_for_finding(
            "ACME", finding_id=42,
            evidence_rows=[{"id": 1, "path": str(original),
                             "redacted_path": str(redacted)}],
            settings=configured_settings,
        )
        assert result.success is True
        assert len(result.archived_paths) == 1
        archived = Path(result.archived_paths[0])
        assert archived.read_bytes() == b"redacted-pngdata"
        # Stored under per-finding folder
        assert archived.parent.name == "42"

    def test_falls_back_to_path_when_no_redacted(self, configured_settings,
                                                    tmp_path: Path) -> None:
        original = tmp_path / "shot.png"
        original.write_bytes(b"original")
        result = finalize_evidence_for_finding(
            "ACME", finding_id=10,
            evidence_rows=[{"id": 1, "path": str(original)}],
            settings=configured_settings,
        )
        assert result.success is True
        assert Path(result.archived_paths[0]).read_bytes() == b"original"

    def test_skips_missing_paths(self, configured_settings,
                                   tmp_path: Path) -> None:
        result = finalize_evidence_for_finding(
            "ACME", finding_id=5,
            evidence_rows=[
                {"id": 1, "path": str(tmp_path / "ghost.png")},
                {"id": 2, "path": None, "redacted_path": None},
            ],
            settings=configured_settings,
        )
        assert result.success is True
        assert len(result.skipped) == 2

    def test_unset_archive_fails_cleanly(self, disabled_settings,
                                           tmp_path: Path) -> None:
        result = finalize_evidence_for_finding(
            "ACME", finding_id=1,
            evidence_rows=[],
            settings=disabled_settings,
        )
        assert result.success is False
        assert "archive_root" in (result.error or "")
