"""Evidence helpers: hashing, ingestion, basic image redaction.

Goals
-----
1. Every piece of evidence is fingerprinted (SHA-256) so we can prove it
   was unaltered between capture and report.
2. Original (un-redacted) evidence stays in ``evidence/raw/`` on the hot side.
3. A redacted copy is created for inclusion in the final report. The
   ``redact_image`` helper here implements rectangular black-box redaction;
   richer GUI-driven redaction lands in Phase 5 (web dashboard).
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

from .paths import to_canonical


def sha256_file(path: Path | str, *, chunk: int = 65536) -> str:
    """Return the hex SHA-256 digest of a file (streamed)."""
    h = hashlib.sha256()
    p = Path(path)
    with p.open("rb") as fp:
        for block in iter(lambda: fp.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class IngestedEvidence:
    """Result of ingesting an evidence file into the engagement store."""

    source: Path
    stored: Path
    sha256: str
    size_bytes: int
    canonical_path: str  # POSIX/WSL form for DB persistence


def ingest_evidence(src: Path | str, dest_dir: Path | str, *, copy: bool = True) -> IngestedEvidence:
    """Copy (or move) evidence into the engagement's ``evidence/raw/`` tree.

    The file is renamed to ``<stem>__<sha256[:12]><suffix>`` so duplicate names
    from different captures don't collide. Returns an ``IngestedEvidence``
    descriptor; persisting the row in SQLite is the caller's responsibility.
    """
    src_path = Path(src)
    if not src_path.exists():
        raise FileNotFoundError(src_path)

    dest_root = Path(dest_dir)
    dest_root.mkdir(parents=True, exist_ok=True)

    digest = sha256_file(src_path)
    short = digest[:12]
    new_name = f"{src_path.stem}__{short}{src_path.suffix}"
    target = dest_root / new_name

    if not target.exists():
        if copy:
            shutil.copy2(src_path, target)
        else:
            shutil.move(str(src_path), str(target))

    return IngestedEvidence(
        source=src_path,
        stored=target,
        sha256=digest,
        size_bytes=target.stat().st_size,
        canonical_path=to_canonical(target),
    )


# ──────────────────────────── Image redaction ────────────────────────────

# Pillow is a hard dep but we import lazily so command-line tools that don't
# touch images stay slim.


@dataclass
class RedactionBox:
    x: int
    y: int
    width: int
    height: int

    def normalised(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.x + self.width, self.y + self.height)


def redact_image(
    src: Path | str,
    dest: Path | str,
    boxes: list[RedactionBox],
    *,
    fill: tuple[int, int, int] = (0, 0, 0),
) -> Path:
    """Draw filled rectangles over ``boxes`` and save to ``dest``.

    Returns the destination path. If ``boxes`` is empty the source is copied
    verbatim — useful for marking an image as 'reviewed, no PII'.
    """
    from PIL import Image, ImageDraw

    src_path = Path(src)
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    if not boxes:
        shutil.copy2(src_path, dest_path)
        return dest_path

    with Image.open(src_path) as im:
        im = im.convert("RGB") if im.mode not in ("RGB", "RGBA") else im.copy()
        draw = ImageDraw.Draw(im)
        for b in boxes:
            draw.rectangle(b.normalised(), fill=fill)
        im.save(dest_path)
    return dest_path


def redact_text(text: str, secrets: list[str], *, replacement: str = "[REDACTED]") -> str:
    """Replace each occurrence of every secret in ``secrets`` with ``replacement``."""
    out = text
    for s in secrets:
        if not s:
            continue
        out = out.replace(s, replacement)
    return out
