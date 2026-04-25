"""YAML procedure loader.

Each procedure (bug_bounty / wp_stress / wifi_pentest) is a YAML document with
this top-level shape::

    id: bb
    name: "Bug Bounty Recon & Vulnerability Assessment"
    description: "..."
    stages:
      - id: stage1
        name: "Passive Domain Intelligence"
        objective: "..."
        steps:
          - id: bb.stage1.crtsh
            ...

Steps must declare ``runtime`` (linux | windows | either) and ``mode``
(auto | walkthrough | hybrid). Auto steps reference a module via the
``module: package.module:callable`` notation. Walkthrough steps carry an
``prompts`` array and optional ``collect`` items.
"""

from __future__ import annotations

import importlib.resources as resources
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALLOWED_MODES = {"auto", "walkthrough", "hybrid"}
ALLOWED_RUNTIMES = {"linux", "windows", "either"}
ALLOWED_COLLECT_KINDS = {"file", "integer", "text", "boolean", "url", "screenshot"}


# ──────────────────────────── Dataclasses ────────────────────────────


@dataclass
class StepCollect:
    prompt: str
    kind: str = "text"
    target: str | None = None
    store: str | None = None


@dataclass
class Step:
    id: str
    name: str
    stage: str
    procedure: str
    mode: str = "auto"
    runtime: str = "either"
    requires: list[str] = field(default_factory=list)
    why: str | None = None
    what_to_collect: list[str] = field(default_factory=list)
    module: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    outputs: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    collect: list[StepCollect] = field(default_factory=list)
    training: dict[str, str] = field(default_factory=dict)
    next: list[str] = field(default_factory=list)

    def is_walkthrough(self) -> bool:
        return self.mode in ("walkthrough", "hybrid")

    def is_automatable(self) -> bool:
        return self.mode in ("auto", "hybrid") and bool(self.module)


@dataclass
class Stage:
    id: str
    name: str
    objective: str | None
    steps: list[Step] = field(default_factory=list)


@dataclass
class Procedure:
    id: str
    name: str
    description: str | None
    source: Path | None  # YAML file path
    stages: list[Stage] = field(default_factory=list)

    def step(self, step_id: str) -> Step:
        for st in self.stages:
            for sp in st.steps:
                if sp.id == step_id:
                    return sp
        raise KeyError(step_id)

    def all_steps(self) -> list[Step]:
        return [sp for st in self.stages for sp in st.steps]


# ──────────────────────────── Loader ────────────────────────────


class ProcedureLoadError(ValueError):
    pass


def _validate_step(raw: dict[str, Any], procedure_id: str, stage_id: str) -> Step:
    sid = raw.get("id")
    if not sid or not isinstance(sid, str):
        raise ProcedureLoadError(f"step missing 'id' in {procedure_id}.{stage_id}")
    name = raw.get("name") or sid
    mode = (raw.get("mode") or "auto").lower()
    runtime = (raw.get("runtime") or "either").lower()
    if mode not in ALLOWED_MODES:
        raise ProcedureLoadError(f"step {sid}: invalid mode '{mode}'")
    if runtime not in ALLOWED_RUNTIMES:
        raise ProcedureLoadError(f"step {sid}: invalid runtime '{runtime}'")

    module = raw.get("module")
    if mode == "auto" and not module:
        raise ProcedureLoadError(f"step {sid}: mode=auto requires 'module'")
    if module and ":" not in module:
        raise ProcedureLoadError(f"step {sid}: 'module' must be 'pkg.mod:callable'")

    collect_raw = raw.get("collect") or []
    collect: list[StepCollect] = []
    for c in collect_raw:
        if not isinstance(c, dict) or "prompt" not in c:
            raise ProcedureLoadError(f"step {sid}: collect entries need 'prompt'")
        kind = (c.get("kind") or "text").lower()
        if kind not in ALLOWED_COLLECT_KINDS:
            raise ProcedureLoadError(f"step {sid}: collect kind '{kind}' invalid")
        collect.append(StepCollect(
            prompt=c["prompt"], kind=kind, target=c.get("target"), store=c.get("store")
        ))

    requires = list(raw.get("requires") or [])
    next_steps = list(raw.get("next") or [])
    outputs = list(raw.get("outputs") or [])
    prompts = list(raw.get("prompts") or [])
    training = dict(raw.get("training") or {})
    what = list(raw.get("what_to_collect") or [])
    params = dict(raw.get("params") or {})

    return Step(
        id=sid, name=name, stage=stage_id, procedure=procedure_id,
        mode=mode, runtime=runtime, requires=requires,
        why=raw.get("why"), what_to_collect=what,
        module=module, params=params,
        outputs=outputs, prompts=prompts, collect=collect,
        training=training, next=next_steps,
    )


def _validate_stage(raw: dict[str, Any], procedure_id: str) -> Stage:
    sid = raw.get("id")
    if not sid:
        raise ProcedureLoadError(f"stage missing 'id' in {procedure_id}")
    steps = [_validate_step(s, procedure_id, sid) for s in (raw.get("steps") or [])]
    return Stage(id=sid, name=raw.get("name") or sid, objective=raw.get("objective"), steps=steps)


def _validate_procedure(raw: dict[str, Any], source: Path | None = None) -> Procedure:
    pid = raw.get("id")
    if not pid:
        raise ProcedureLoadError(f"procedure missing 'id' (source={source})")
    stages = [_validate_stage(s, pid) for s in (raw.get("stages") or [])]
    proc = Procedure(
        id=pid, name=raw.get("name") or pid,
        description=raw.get("description"),
        source=source, stages=stages,
    )
    # Cross-step validation: every 'next' must point at a known step.
    known = {sp.id for sp in proc.all_steps()}
    for sp in proc.all_steps():
        bad = [n for n in sp.next if n not in known and not n.startswith(f"{pid}.")]
        # Allow forward references to other procedures (e.g. bb.stage4.zap)
        # by relaxing the requirement to same-procedure ids; just sanity check.
        for n in sp.next:
            if n not in known and n.startswith(f"{pid}."):
                raise ProcedureLoadError(
                    f"step {sp.id}: 'next' references unknown step '{n}'"
                )
        del bad
    return proc


def load_procedure(path: Path | str) -> Procedure:
    p = Path(path)
    with p.open("r", encoding="utf-8") as fp:
        raw = yaml.safe_load(fp)
    if not isinstance(raw, dict):
        raise ProcedureLoadError(f"procedure file must be a YAML mapping: {p}")
    return _validate_procedure(raw, source=p)


def load_procedures(paths: Iterable[Path | str]) -> dict[str, Procedure]:
    procs: dict[str, Procedure] = {}
    for path in paths:
        proc = load_procedure(path)
        if proc.id in procs:
            raise ProcedureLoadError(f"duplicate procedure id '{proc.id}': {path}")
        procs[proc.id] = proc
    return procs


class ProcedureLoader:
    """Discover and cache procedure YAML files.

    Default lookup path is the package data directory ``twisted/procedures/``.
    Tests and CLI flags can pass an explicit ``search_paths`` list.
    """

    def __init__(self, search_paths: Iterable[Path | str] | None = None):
        self._paths: list[Path] = [Path(p) for p in (search_paths or [])]
        self._cache: dict[str, Procedure] | None = None

    def discover(self) -> list[Path]:
        files: list[Path] = []
        for root in self._paths:
            if root.is_file() and root.suffix in (".yaml", ".yml"):
                files.append(root)
            elif root.is_dir():
                files.extend(sorted(root.glob("*.yaml")))
                files.extend(sorted(root.glob("*.yml")))
        if not files:
            # Fall back to packaged procedures.
            try:
                pkg = resources.files("twisted.procedures")
                for f in pkg.iterdir():
                    if f.suffix in (".yaml", ".yml"):
                        files.append(Path(str(f)))
            except (FileNotFoundError, ModuleNotFoundError):
                pass
        return files

    def all(self) -> dict[str, Procedure]:
        if self._cache is None:
            self._cache = load_procedures(self.discover())
        return self._cache

    def get(self, procedure_id: str) -> Procedure:
        if procedure_id not in self.all():
            raise KeyError(procedure_id)
        return self.all()[procedure_id]

    def step(self, step_id: str) -> Step:
        for proc in self.all().values():
            try:
                return proc.step(step_id)
            except KeyError:
                continue
        raise KeyError(step_id)

    def reload(self) -> None:
        self._cache = None
