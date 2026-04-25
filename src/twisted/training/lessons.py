"""Markdown lesson loader.

Lesson file format::

    ---
    step_id: bb.stage1.crtsh
    procedure: bb
    stage: stage1
    title: Certificate Transparency Log Harvesting
    estimated_minutes: 8
    ---

    ## What We Are Doing
    ...prose...

    ## Why
    ...prose...

    ## How
    ...prose / steps / commands...

    ## Practice
    Run the corresponding step against the OWASP Juice Shop lab:

    ```bash
    twisted step run bb.stage1.crtsh --param domain=juice-shop.local
    ```

The frontmatter is optional. If it's missing, defaults are derived
from the file path. Section headings are detected case-insensitively
and a few synonyms are accepted (e.g. "Why We Do This" → "why",
"How This Data Will Be Used" → "how", "Step-by-Step Execution" →
"how").
"""

from __future__ import annotations

import importlib.resources as resources
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Map a section heading (lowercased) to its canonical key. The first
# alias that hits wins. Anything not matched is kept under its
# verbatim title in ``Lesson.extra_sections``.
_SECTION_ALIASES: dict[str, str] = {
    "what we are doing": "what",
    "what": "what",
    "objective": "what",
    "rationale": "why",
    "why": "why",
    "why we do this": "why",
    "how this data will be used": "how",
    "how to use it": "how",
    "how": "how",
    "step-by-step execution": "how",
    "steps": "how",
    "procedure": "how",
    "what to collect": "what_to_collect",
    "tools used": "tools",
    "tools required": "tools",
    "tools used in this phase": "tools",
    "practice": "practice",
}

CANONICAL_SECTIONS = ("what", "why", "how", "what_to_collect", "tools", "practice")


class LessonNotFound(KeyError):
    pass


@dataclass
class Lesson:
    step_id: str
    procedure: str
    stage: str | None
    title: str
    body: str  # full markdown body (after frontmatter)
    sections: dict[str, str] = field(default_factory=dict)  # canonical-key → markdown
    extra_sections: dict[str, str] = field(default_factory=dict)
    estimated_minutes: int | None = None
    source_path: Path | None = None

    @property
    def has_practice(self) -> bool:
        return bool(self.sections.get("practice"))


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$", re.MULTILINE)


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, text[m.end():]


def _canonicalise_section(title: str) -> str | None:
    return _SECTION_ALIASES.get(title.strip().lower())


def _split_sections(body: str) -> tuple[dict[str, str], dict[str, str]]:
    """Split body markdown by ## or ### headings into canonical buckets.

    Returns (canonical_sections, extra_sections). A section runs from
    its heading up to the next ## / ### / # heading.
    """
    canonical: dict[str, str] = {}
    extra: dict[str, str] = {}
    headings = list(_HEADING_RE.finditer(body))
    if not headings:
        return canonical, extra
    for i, h in enumerate(headings):
        level = len(h.group(1))
        if level not in (2, 3):  # only treat ## / ### as sections
            continue
        title = h.group(2)
        start = h.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(body)
        content = body[start:end].strip()
        key = _canonicalise_section(title)
        if key:
            # If multiple headings map to the same key, append.
            if key in canonical:
                canonical[key] = canonical[key] + "\n\n" + content
            else:
                canonical[key] = content
        else:
            extra[title] = content
    return canonical, extra


def parse_lesson(text: str, *, source: Path | None = None) -> Lesson:
    meta, body = _parse_frontmatter(text)
    sections, extras = _split_sections(body)

    step_id = meta.get("step_id")
    if not step_id and source is not None:
        step_id = _step_id_from_path(source)
    if not step_id:
        raise ValueError("lesson missing step_id (no frontmatter and no path)")

    procedure = meta.get("procedure") or step_id.split(".", 1)[0]
    stage = meta.get("stage")
    if stage is None and "." in step_id:
        parts = step_id.split(".")
        if len(parts) >= 3:
            stage = parts[1]
    title = meta.get("title") or step_id
    minutes = meta.get("estimated_minutes")
    if minutes is not None:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            minutes = None

    return Lesson(
        step_id=step_id, procedure=procedure, stage=stage, title=title,
        body=body.strip(), sections=sections, extra_sections=extras,
        estimated_minutes=minutes, source_path=source,
    )


def _step_id_from_path(path: Path) -> str | None:
    """Recover a step_id like ``bb.stage1.crtsh`` from a file path like
    ``training/lessons/bb/stage1/crtsh.md``."""
    parts = list(path.with_suffix("").parts)
    if "lessons" in parts:
        i = parts.index("lessons")
        rest = parts[i + 1:]
        if rest:
            return ".".join(rest)
    return None


# ──────────────────────────── Repository ────────────────────────────


class LessonRepo:
    """Discovers and caches lesson files.

    Search order:
      1. ``search_paths`` (explicit paths passed to the constructor).
      2. The packaged ``twisted/training/lessons/`` directory.
    """

    def __init__(self, search_paths: list[Path] | None = None):
        self._search_paths: list[Path] = list(search_paths or [])
        self._cache: dict[str, Lesson] | None = None

    def _discover_files(self) -> Iterator[Path]:
        for root in self._search_paths:
            if root.is_file() and root.suffix == ".md":
                yield root
            elif root.is_dir():
                yield from sorted(root.rglob("*.md"))
        # Fall back to packaged lessons if the explicit paths didn't
        # turn anything up (or weren't given).
        if not self._search_paths:
            try:
                pkg = resources.files("twisted.training.lessons")
                yield from _walk_pkg(pkg)
            except (FileNotFoundError, ModuleNotFoundError):
                return

    def all(self) -> dict[str, Lesson]:
        if self._cache is not None:
            return self._cache
        out: dict[str, Lesson] = {}
        for path in self._discover_files():
            try:
                lesson = parse_lesson(path.read_text(encoding="utf-8"), source=path)
            except (OSError, ValueError):
                continue
            out[lesson.step_id] = lesson
        self._cache = out
        return out

    def get(self, step_id: str) -> Lesson:
        lessons = self.all()
        if step_id not in lessons:
            raise LessonNotFound(step_id)
        return lessons[step_id]

    def for_procedure(self, procedure_id: str) -> list[Lesson]:
        return [lsn for lsn in self.all().values() if lsn.procedure == procedure_id]

    def reload(self) -> None:
        self._cache = None


def _walk_pkg(traversable) -> Iterator[Path]:
    """Recurse through an importlib.resources Traversable yielding
    Path-like objects for .md files."""
    for entry in traversable.iterdir():
        try:
            if entry.is_dir():
                yield from _walk_pkg(entry)
            elif entry.is_file() and entry.name.endswith(".md"):
                yield Path(str(entry))
        except (FileNotFoundError, NotADirectoryError):
            continue
