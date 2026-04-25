"""Unit tests for the PII redaction helpers."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from PIL import Image

from twisted.core.redact import Rectangle, redact_bytes, redact_file


def _png_bytes(width: int = 100, height: int = 60,
               color: tuple[int, int, int] = (200, 50, 50)) -> bytes:
    img = Image.new("RGB", (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestRectangle:
    def test_box_property(self) -> None:
        r = Rectangle(x=10, y=20, width=30, height=40)
        assert r.box == (10, 20, 40, 60)

    def test_from_dict_coerces(self) -> None:
        r = Rectangle.from_dict({"x": "5", "y": "6", "width": "7", "height": "8"})
        assert (r.x, r.y, r.width, r.height) == (5, 6, 7, 8)

    def test_from_dict_defaults_to_zero(self) -> None:
        r = Rectangle.from_dict({})
        assert r.box == (0, 0, 0, 0)


class TestRedactBytes:
    def test_blacks_out_rectangle(self) -> None:
        src = _png_bytes()
        out, size = redact_bytes(src, [Rectangle(20, 10, 40, 30)])
        assert size == (100, 60)
        # Open the result and verify pixels inside the rectangle are
        # black, while pixels outside are still the source colour.
        result = Image.open(io.BytesIO(out)).convert("RGB")
        assert result.getpixel((40, 25)) == (0, 0, 0)         # inside
        assert result.getpixel((5, 5)) == (200, 50, 50)        # outside

    def test_zero_size_rectangle_is_noop(self) -> None:
        src = _png_bytes()
        out, _ = redact_bytes(src, [Rectangle(10, 10, 0, 0)])
        result = Image.open(io.BytesIO(out)).convert("RGB")
        assert result.getpixel((10, 10)) == (200, 50, 50)

    def test_multiple_rectangles_apply_independently(self) -> None:
        src = _png_bytes(width=200, height=100)
        out, _ = redact_bytes(src, [
            Rectangle(10, 10, 30, 30),
            Rectangle(120, 50, 40, 30),
        ])
        result = Image.open(io.BytesIO(out)).convert("RGB")
        assert result.getpixel((20, 20)) == (0, 0, 0)
        assert result.getpixel((140, 70)) == (0, 0, 0)
        assert result.getpixel((80, 80)) == (200, 50, 50)


class TestRedactFile:
    def test_writes_dest_with_sha(self, tmp_path: Path) -> None:
        src = tmp_path / "screenshot.png"
        src.write_bytes(_png_bytes())
        dest = tmp_path / "redacted" / "screenshot.png"
        result = redact_file(src, dest, [Rectangle(10, 10, 20, 20)])
        assert dest.exists()
        assert result.sha256 and len(result.sha256) == 64
        assert result.width == 100
        assert result.height == 60
        assert result.rectangles_applied == 1

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        src = tmp_path / "in.png"
        src.write_bytes(_png_bytes())
        dest = tmp_path / "deeply" / "nested" / "out.png"
        result = redact_file(src, dest, [])
        assert dest.parent.exists()
        # No rectangles applied, but file still written
        assert result.rectangles_applied == 0
        assert result.sha256

    def test_unknown_format_raises_pillow_error(self, tmp_path: Path) -> None:
        from PIL import UnidentifiedImageError
        src = tmp_path / "not_an_image.png"
        src.write_bytes(b"not actually an image")
        with pytest.raises(UnidentifiedImageError):
            redact_file(src, tmp_path / "out.png", [])
