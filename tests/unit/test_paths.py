"""Tests for cross-host path translation."""

from __future__ import annotations

import os

import pytest

from twisted.core import paths


class TestToWsl:
    @pytest.mark.parametrize(
        ("inp", "expected"),
        [
            ("C:\\Users\\awhwt\\foo.txt", "/mnt/c/Users/awhwt/foo.txt"),
            ("c:\\Users\\awhwt\\foo.txt", "/mnt/c/Users/awhwt/foo.txt"),
            ("D:\\", "/mnt/d/"),
            ("D:/", "/mnt/d/"),
            ("C:/Users/awhwt/OneDrive/Desktop/Twisted",
             "/mnt/c/Users/awhwt/OneDrive/Desktop/Twisted"),
            ("/mnt/c/Users/awhwt/foo.txt", "/mnt/c/Users/awhwt/foo.txt"),
            ("/home/null/twisted_suite", "/home/null/twisted_suite"),
            ("relative\\path\\foo.txt", "relative/path/foo.txt"),
            ("", ""),
        ],
    )
    def test_basic_conversions(self, inp: str, expected: str) -> None:
        assert paths.to_wsl(inp) == expected

    def test_unc_wsl_dollar(self) -> None:
        result = paths.to_wsl(r"\\wsl$\Ubuntu\home\null\twisted_suite")
        assert result == "/home/null/twisted_suite"

    def test_unc_wsl_localhost(self) -> None:
        result = paths.to_wsl(r"\\wsl.localhost\Ubuntu\home\null\foo")
        assert result == "/home/null/foo"


class TestToWindows:
    @pytest.mark.parametrize(
        ("inp", "expected"),
        [
            ("/mnt/c/Users/awhwt/foo.txt", "C:\\Users\\awhwt\\foo.txt"),
            ("/mnt/d/", "D:\\"),
            ("/mnt/c/Users/awhwt", "C:\\Users\\awhwt"),
            ("C:\\already\\windows", "C:\\already\\windows"),
        ],
    )
    def test_mnt_drive_conversions(self, inp: str, expected: str) -> None:
        assert paths.to_windows(inp) == expected

    def test_posix_to_unc_default_distro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TWISTED_WSL_DISTRO", raising=False)
        result = paths.to_windows("/home/null/twisted_suite")
        assert result == r"\\wsl$\Ubuntu\home\null\twisted_suite"

    def test_posix_to_unc_custom_distro(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWISTED_WSL_DISTRO", "Kali")
        result = paths.to_windows("/home/null/foo")
        assert result == r"\\wsl$\Kali\home\null\foo"


class TestRoundTrip:
    @pytest.mark.parametrize(
        "path",
        [
            "C:\\Users\\awhwt\\OneDrive\\Desktop\\Twisted\\bug_bounty_procedure.docx",
            "/mnt/c/Users/awhwt/OneDrive/Desktop/Twisted/bug_bounty_procedure.docx",
            "/home/null/twisted_suite/data/twisted.db",
        ],
    )
    def test_round_trip_through_wsl(self, path: str) -> None:
        wsl_form = paths.to_wsl(path)
        # to_wsl is idempotent
        assert paths.to_wsl(wsl_form) == wsl_form
        # converting to windows then back yields same wsl form
        win_form = paths.to_windows(wsl_form)
        assert paths.to_wsl(win_form) == wsl_form


class TestEnvDetection:
    def test_force_wsl_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWISTED_FORCE_WSL", "1")
        assert paths.is_wsl() is True

    def test_force_wsl_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWISTED_FORCE_WSL", "0")
        assert paths.is_wsl() is False

    def test_to_native_uses_current_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # On a WSL/Linux host to_native returns POSIX form for /mnt paths
        if os.name != "nt":
            assert paths.to_native("C:\\Users\\foo") == "/mnt/c/Users/foo"

    def test_to_canonical_is_wsl_form(self) -> None:
        assert paths.to_canonical("C:\\Users\\foo") == "/mnt/c/Users/foo"
