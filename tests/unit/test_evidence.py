"""Tests for evidence helpers (hashing, ingest, image redaction)."""

from __future__ import annotations

from pathlib import Path

import pytest

from twisted.core.evidence import (
    RedactionBox,
    ingest_evidence,
    redact_image,
    redact_text,
    sha256_bytes,
    sha256_file,
)


class TestSha256:
    def test_known_hash_for_bytes(self) -> None:
        # echo -n 'hello' | sha256sum -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert (
            sha256_bytes(b"hello")
            == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_file_hash_matches_bytes_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_bytes(b"hello")
        assert sha256_file(f) == sha256_bytes(b"hello")

    def test_streaming_handles_chunk_boundary(self, tmp_path: Path) -> None:
        # Force a multi-chunk read.
        f = tmp_path / "big.bin"
        data = b"x" * (65536 * 3 + 17)
        f.write_bytes(data)
        assert sha256_file(f, chunk=65536) == sha256_bytes(data)


class TestIngest:
    def test_ingest_copies_and_renames_with_digest_suffix(self, tmp_path: Path) -> None:
        src = tmp_path / "shot.png"
        src.write_bytes(b"PNG-CONTENT")
        dest_dir = tmp_path / "engagements" / "ovh" / "evidence" / "raw"

        result = ingest_evidence(src, dest_dir)

        assert result.stored.exists()
        assert result.sha256 == sha256_bytes(b"PNG-CONTENT")
        assert result.size_bytes == len(b"PNG-CONTENT")
        # digest-suffixed name
        assert result.sha256[:12] in result.stored.name
        assert result.stored.suffix == ".png"
        # source still present (copy mode)
        assert src.exists()
        # canonical_path is POSIX form
        assert "\\" not in result.canonical_path

    def test_ingest_move_mode_removes_source(self, tmp_path: Path) -> None:
        src = tmp_path / "raw" / "shot.png"
        src.parent.mkdir()
        src.write_bytes(b"PNG-CONTENT")
        dest_dir = tmp_path / "evidence"

        ingest_evidence(src, dest_dir, copy=False)

        assert not src.exists()
        # exactly one file in dest_dir
        files = list(dest_dir.iterdir())
        assert len(files) == 1

    def test_ingest_dedup_when_same_sha(self, tmp_path: Path) -> None:
        src1 = tmp_path / "a" / "shot.png"
        src1.parent.mkdir()
        src1.write_bytes(b"identical")
        src2 = tmp_path / "b" / "shot.png"
        src2.parent.mkdir()
        src2.write_bytes(b"identical")
        dest = tmp_path / "evidence"

        r1 = ingest_evidence(src1, dest)
        r2 = ingest_evidence(src2, dest)

        # Same content -> same target file
        assert r1.stored == r2.stored
        assert r1.sha256 == r2.sha256
        assert len(list(dest.iterdir())) == 1

    def test_ingest_missing_source_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ingest_evidence(tmp_path / "nope.png", tmp_path / "evidence")


class TestImageRedaction:
    @pytest.fixture
    def sample_png(self, tmp_path: Path) -> Path:
        from PIL import Image

        path = tmp_path / "sample.png"
        Image.new("RGB", (100, 100), color=(255, 255, 255)).save(path)
        return path

    def test_redaction_blacks_out_box(self, sample_png: Path, tmp_path: Path) -> None:
        from PIL import Image

        out = tmp_path / "redacted.png"
        boxes = [RedactionBox(x=10, y=10, width=20, height=20)]
        result = redact_image(sample_png, out, boxes)
        assert result.exists()

        with Image.open(out) as im:
            # Inside box should be black, outside still white
            assert im.getpixel((20, 20)) == (0, 0, 0)
            assert im.getpixel((90, 90)) == (255, 255, 255)

    def test_empty_boxes_just_copies(self, sample_png: Path, tmp_path: Path) -> None:
        from PIL import Image

        out = tmp_path / "noredact.png"
        redact_image(sample_png, out, boxes=[])
        with Image.open(out) as im:
            assert im.getpixel((50, 50)) == (255, 255, 255)


class TestRedactText:
    def test_replace_each_secret(self) -> None:
        text = "user=root pw=hunter2 token=abc.def.ghi"
        out = redact_text(text, ["hunter2", "abc.def.ghi"])
        assert "hunter2" not in out
        assert "abc.def.ghi" not in out
        assert out.count("[REDACTED]") == 2

    def test_empty_secrets_skipped(self) -> None:
        assert redact_text("hello", ["", None]) == "hello"  # type: ignore[list-item]
