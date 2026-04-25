"""Tests for storage layout helpers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from twisted.core.storage import (
    ArchivePaths,
    EngagementPaths,
    finalize_evidence,
    slugify,
    stage_folder,
    write_artifact,
)


class TestSlugify:
    @pytest.mark.parametrize(
        ("inp", "expected"),
        [
            ("OVH", "ovh"),
            ("OVH Bug Bounty", "ovh_bug_bounty"),
            ("ACME / Co.", "acme_co"),
            ("Über Co", "ber_co"),  # non-ascii stripped
            ("....", "unnamed"),
            ("a.b-c_d", "a.b-c_d"),
        ],
    )
    def test_slugify(self, inp: str, expected: str) -> None:
        assert slugify(inp) == expected

    def test_max_len(self) -> None:
        assert len(slugify("x" * 200, max_len=20)) == 20


class TestStageFolder:
    @pytest.mark.parametrize(
        ("inp", "expected"),
        [
            ("stage1", "stage1"),
            ("Stage 1", "stage-1"),
            ("Phase 2 — Stress", "phase-2-stress"),
            (None, "misc"),
            ("", "misc"),
        ],
    )
    def test_stage_folder(self, inp: str | None, expected: str) -> None:
        assert stage_folder(inp) == expected


class TestEngagementPaths:
    def test_paths_resolved_under_data_root(self, isolated_settings) -> None:
        ep = EngagementPaths.for_engagement("OVH", isolated_settings)
        assert ep.root == isolated_settings.engagements_dir / "ovh"
        assert ep.raw == ep.root / "raw"
        assert ep.captures == ep.root / "captures"
        assert ep.evidence_raw == ep.root / "evidence" / "raw"

    def test_ensure_creates_dirs(self, isolated_settings) -> None:
        ep = EngagementPaths.for_engagement("OVH", isolated_settings).ensure()
        assert ep.root.exists()
        assert ep.raw.exists()
        assert ep.captures.exists()
        assert ep.evidence_raw.exists()
        assert ep.logs.exists()

    def test_step_dir_and_artifact(self, isolated_settings) -> None:
        ep = EngagementPaths.for_engagement("OVH", isolated_settings).ensure()
        ts = datetime(2026, 4, 24, 22, 30, 15)
        path = ep.step_artifact("Stage 1 Passive", "bb.stage1.crtsh", "json", timestamp=ts)
        assert path.parent == ep.raw / "stage-1-passive"
        assert path.name == "bb_stage1_crtsh_20260424_223015.json"
        assert path.parent.exists()


class TestArchivePaths:
    def test_archive_disabled_when_unset(self, isolated_settings) -> None:
        # isolated_settings sets TWISTED_ARCHIVE_ROOT="" -> archive_root None
        assert isolated_settings.archive_root is None
        assert ArchivePaths.for_engagement("OVH", isolated_settings) is None

    def test_archive_enabled_when_set(self, tmp_path: Path, isolated_settings, monkeypatch) -> None:
        archive = tmp_path / "OneDrive" / "Twisted" / "data"
        archive.mkdir(parents=True)
        monkeypatch.setenv("TWISTED_ARCHIVE_ROOT", str(archive))
        from twisted.core.settings import Settings, reset_settings
        new = Settings()
        reset_settings(new)
        try:
            ap = ArchivePaths.for_engagement("OVH", new)
            assert ap is not None
            assert ap.root == archive / "engagements" / "ovh"
            ap.ensure()
            assert ap.reports.exists()
            assert ap.evidence.exists()
        finally:
            reset_settings(isolated_settings)


class TestArtifactIO:
    def test_write_artifact_creates_parents(self, isolated_settings) -> None:
        target = isolated_settings.data_root / "engagements" / "ovh" / "raw" / "stage-1" / "x.json"
        result = write_artifact(target, '{"hello": "world"}')
        assert target.exists()
        assert target.read_text() == '{"hello": "world"}'
        assert str(result) == str(target)

    def test_write_artifact_bytes(self, isolated_settings) -> None:
        target = isolated_settings.data_root / "captures" / "x.bin"
        write_artifact(target, b"\x00\x01\x02")
        assert target.read_bytes() == b"\x00\x01\x02"

    def test_finalize_evidence_copies_to_dest(self, tmp_path: Path) -> None:
        src = tmp_path / "raw" / "shot.png"
        src.parent.mkdir()
        src.write_bytes(b"PNG-content")
        dest_dir = tmp_path / "OneDrive" / "evidence" / "finding-42"
        out = finalize_evidence(src, dest_dir)
        assert out.exists()
        assert out.read_bytes() == b"PNG-content"
        # Source still present (copy, not move)
        assert src.exists()
