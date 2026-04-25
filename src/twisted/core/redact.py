"""PII redaction for screenshots.

Takes an image plus a list of axis-aligned rectangles (in image-pixel
coordinates) and writes a redacted copy with each rectangle filled in
solid black. Designed for the dashboard's in-browser tool but usable
from the CLI / a worker too.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw


@dataclass
class Rectangle:
    x: int
    y: int
    width: int
    height: int

    @classmethod
    def from_dict(cls, raw: dict) -> Rectangle:
        return cls(
            x=int(raw.get("x", 0)),
            y=int(raw.get("y", 0)),
            width=int(raw.get("width", 0)),
            height=int(raw.get("height", 0)),
        )

    @property
    def box(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.x + self.width, self.y + self.height)


@dataclass
class RedactionResult:
    src_path: Path
    redacted_path: Path
    sha256: str
    width: int
    height: int
    rectangles_applied: int


def redact_bytes(image_bytes: bytes, rectangles: list[Rectangle],
                 fill: str = "black") -> tuple[bytes, tuple[int, int]]:
    """Apply ``rectangles`` to the in-memory image and return the
    redacted PNG bytes + (width, height)."""
    src = Image.open(io.BytesIO(image_bytes))
    src.load()
    img = src.convert("RGB") if src.mode not in ("RGB", "RGBA") else src.copy()
    draw = ImageDraw.Draw(img)
    for rect in rectangles:
        if rect.width <= 0 or rect.height <= 0:
            continue
        draw.rectangle(rect.box, fill=fill)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), img.size


def redact_file(src: Path, dest: Path, rectangles: list[Rectangle],
                *, fill: str = "black") -> RedactionResult:
    """Read ``src``, redact, write to ``dest`` (creating parents),
    and return a RedactionResult with the SHA-256 of the redacted
    bytes for evidence integrity."""
    src = Path(src)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload, size = redact_bytes(src.read_bytes(), rectangles, fill=fill)
    dest.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()
    return RedactionResult(
        src_path=src, redacted_path=dest, sha256=sha,
        width=size[0], height=size[1],
        rectangles_applied=sum(1 for r in rectangles
                                if r.width > 0 and r.height > 0),
    )
