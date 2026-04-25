"""Unit tests for the training lesson loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from twisted.training.lessons import (
    Lesson,
    LessonNotFound,
    LessonRepo,
    parse_lesson,
)


class TestParseLesson:
    def test_full_frontmatter_and_canonical_sections(self) -> None:
        text = """---
step_id: bb.stage1.crtsh
procedure: bb
stage: stage1
title: Certificate Transparency Log Harvesting
estimated_minutes: 8
---

## What We Are Doing

CT logs are public, append-only records of every issued certificate.

## Why

Forgotten subdomains keep their certs in CT logs forever.

## How

Search crt.sh with `%.example.com`.
"""
        lsn = parse_lesson(text)
        assert lsn.step_id == "bb.stage1.crtsh"
        assert lsn.procedure == "bb"
        assert lsn.stage == "stage1"
        assert lsn.title.startswith("Certificate Transparency")
        assert lsn.estimated_minutes == 8
        assert "what" in lsn.sections
        assert "why" in lsn.sections
        assert "how" in lsn.sections
        assert "CT logs are public" in lsn.sections["what"]
        assert "Forgotten subdomains" in lsn.sections["why"]
        assert "%.example.com" in lsn.sections["how"]

    def test_no_frontmatter_uses_path(self, tmp_path: Path) -> None:
        f = tmp_path / "lessons" / "bb" / "stage1" / "crtsh.md"
        f.parent.mkdir(parents=True)
        f.write_text("## How\n\nbody\n")
        lsn = parse_lesson(f.read_text(), source=f)
        assert lsn.step_id == "bb.stage1.crtsh"
        assert lsn.procedure == "bb"
        assert lsn.stage == "stage1"
        assert lsn.sections["how"] == "body"

    def test_section_aliases_canonicalise(self) -> None:
        text = """---
step_id: bb.stage1.dns_enum
procedure: bb
stage: stage1
title: DNS
---

## Objective

Map records.

## Rationale

Why we map them.

## Step-by-Step Execution

dig +short A example.com
"""
        lsn = parse_lesson(text)
        assert "what" in lsn.sections
        assert "why" in lsn.sections
        assert "how" in lsn.sections
        assert lsn.sections["what"].startswith("Map records")
        assert lsn.sections["why"].startswith("Why we map")
        assert "dig +short" in lsn.sections["how"]

    def test_empty_frontmatter_falls_back_to_path(self, tmp_path: Path) -> None:
        f = tmp_path / "lessons" / "wifi" / "phase1" / "monitor_mode.md"
        f.parent.mkdir(parents=True)
        f.write_text("body only\n")
        lsn = parse_lesson(f.read_text(), source=f)
        assert lsn.step_id == "wifi.phase1.monitor_mode"
        assert lsn.procedure == "wifi"
        assert lsn.stage == "phase1"

    def test_missing_step_id_with_no_path_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_lesson("## How\n\nbody\n")


class TestLessonRepo:
    def test_loads_from_explicit_path(self, tmp_path: Path) -> None:
        root = tmp_path / "lessons"
        (root / "bb" / "stage1").mkdir(parents=True)
        (root / "bb" / "stage1" / "crtsh.md").write_text(
            "---\nstep_id: bb.stage1.crtsh\nprocedure: bb\n"
            "stage: stage1\ntitle: CT\n---\n\n## What\n\ntext\n"
        )
        repo = LessonRepo(search_paths=[root])
        all_lessons = repo.all()
        assert "bb.stage1.crtsh" in all_lessons
        lsn = repo.get("bb.stage1.crtsh")
        assert isinstance(lsn, Lesson)
        assert lsn.title == "CT"

    def test_for_procedure_filters(self, tmp_path: Path) -> None:
        root = tmp_path / "lessons"
        for proc, sid in [("bb", "bb.stage1.crtsh"),
                          ("bb", "bb.stage2.subfinder"),
                          ("wifi", "wifi.phase1.monitor_mode")]:
            (root / proc / sid.split(".")[1]).mkdir(parents=True, exist_ok=True)
            (root / proc / sid.split(".")[1] / f"{sid.split('.')[-1]}.md").write_text(
                f"---\nstep_id: {sid}\nprocedure: {proc}\n"
                f"stage: {sid.split('.')[1]}\ntitle: x\n---\n\n## What\n\nx\n"
            )
        repo = LessonRepo(search_paths=[root])
        bb_lessons = repo.for_procedure("bb")
        assert {lsn.step_id for lsn in bb_lessons} == {
            "bb.stage1.crtsh", "bb.stage2.subfinder",
        }
        wifi_lessons = repo.for_procedure("wifi")
        assert {lsn.step_id for lsn in wifi_lessons} == {"wifi.phase1.monitor_mode"}

    def test_get_unknown_raises(self, tmp_path: Path) -> None:
        repo = LessonRepo(search_paths=[tmp_path])
        with pytest.raises(LessonNotFound):
            repo.get("bb.stage1.nonexistent")

    def test_packaged_lessons_load_when_no_search_paths(self) -> None:
        """The default LessonRepo (no search_paths) should pick up the
        packaged training/lessons/ tree populated by the extractor."""
        repo = LessonRepo()
        all_lessons = repo.all()
        # Should at least include the bb stage1 lessons we shipped
        assert "bb.stage1.crtsh" in all_lessons
        assert "wp_stress.phase1.baseline_ab" in all_lessons
