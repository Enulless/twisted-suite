"""Tests for procedure YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from twisted.core.procedures import (
    Procedure,
    ProcedureLoader,
    Step,
    load_procedure,
)
from twisted.core.procedures.loader import ProcedureLoadError


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


VALID_YAML = """
id: bb
name: "Bug Bounty"
stages:
  - id: stage1
    name: "Stage 1"
    steps:
      - id: bb.stage1.crtsh
        name: "CT Logs"
        mode: auto
        runtime: either
        requires: [network]
        why: "..."
        module: twisted.modules.recon.crtsh:run
        params: { domain: "{{engagement.primary_domain}}" }
        next: [bb.stage1.dns]
      - id: bb.stage1.dns
        name: "DNS"
        mode: auto
        runtime: linux
        module: twisted.modules.recon.dns_enum:run
"""


class TestLoadProcedure:
    def test_load_valid_procedure(self, tmp_path: Path) -> None:
        f = _write(tmp_path / "bb.yaml", VALID_YAML)
        proc = load_procedure(f)
        assert proc.id == "bb"
        assert len(proc.stages) == 1
        assert len(proc.stages[0].steps) == 2
        step = proc.step("bb.stage1.crtsh")
        assert step.runtime == "either"
        assert step.module == "twisted.modules.recon.crtsh:run"
        assert step.is_automatable()
        assert "network" in step.requires

    def test_walkthrough_step_no_module_required(self, tmp_path: Path) -> None:
        body = """
id: bb
name: bb
stages:
  - id: s1
    name: S1
    steps:
      - id: bb.s1.zap
        name: ZAP
        mode: walkthrough
        runtime: windows
        prompts: ["open zap"]
        collect:
          - prompt: "upload report"
            kind: file
"""
        proc = load_procedure(_write(tmp_path / "bb.yaml", body))
        step = proc.step("bb.s1.zap")
        assert step.is_walkthrough()
        assert not step.is_automatable()
        assert step.collect[0].kind == "file"


class TestValidationFailures:
    @pytest.mark.parametrize(
        ("body", "needle"),
        [
            ("id: bb\nstages: []", None),  # ok
            ("name: x\nstages: []", "missing 'id'"),
            (
                "id: bb\nstages:\n  - name: s\n    steps: []",
                "stage missing 'id'",
            ),
            (
                "id: bb\nstages:\n  - id: s\n    steps:\n      - mode: auto",
                "step missing 'id'",
            ),
            (
                "id: bb\nstages:\n  - id: s\n    steps:\n      - id: a\n        mode: auto",
                "mode=auto requires 'module'",
            ),
            (
                "id: bb\nstages:\n  - id: s\n    steps:\n      - id: a\n        mode: weird\n        module: x:y",
                "invalid mode",
            ),
            (
                "id: bb\nstages:\n  - id: s\n    steps:\n      - id: a\n        runtime: lunix\n        module: x:y",
                "invalid runtime",
            ),
            (
                "id: bb\nstages:\n  - id: s\n    steps:\n      - id: a\n        module: noColon",
                "must be 'pkg.mod:callable'",
            ),
        ],
    )
    def test_invalid_documents(self, tmp_path: Path, body: str, needle: str | None) -> None:
        f = _write(tmp_path / "x.yaml", body)
        if needle is None:
            load_procedure(f)
        else:
            with pytest.raises(ProcedureLoadError, match=needle):
                load_procedure(f)

    def test_unknown_next_in_same_procedure_raises(self, tmp_path: Path) -> None:
        body = """
id: bb
stages:
  - id: s1
    steps:
      - id: bb.s1.a
        mode: auto
        module: x:y
        next: [bb.s1.zzz]
"""
        with pytest.raises(ProcedureLoadError, match="next.*unknown"):
            load_procedure(_write(tmp_path / "x.yaml", body))


class TestProcedureLoader:
    def test_loader_discovers_packaged_procedure(self) -> None:
        loader = ProcedureLoader()
        procs = loader.all()
        assert "bb" in procs
        bb = loader.get("bb")
        assert isinstance(bb, Procedure)
        # Sanity check that the seed procedure has at least one auto step
        # and one walkthrough step (used by Phase 1 e2e demo).
        steps = bb.all_steps()
        modes = {s.mode for s in steps}
        assert "auto" in modes
        assert "walkthrough" in modes

    def test_loader_with_explicit_dir(self, tmp_path: Path) -> None:
        d = tmp_path / "procs"
        _write(d / "bb.yaml", VALID_YAML)
        loader = ProcedureLoader(search_paths=[d])
        assert "bb" in loader.all()
        assert loader.step("bb.stage1.crtsh").id == "bb.stage1.crtsh"
        with pytest.raises(KeyError):
            loader.step("bb.nope")

    def test_step_lookup_across_procedures(self, tmp_path: Path) -> None:
        loader = ProcedureLoader()
        s = loader.step("bb.stage1.crtsh")
        assert isinstance(s, Step)
        assert s.runtime in ("linux", "windows", "either")
