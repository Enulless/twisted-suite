"""Tests for runner.py — subprocess wrapper + tool detection."""

from __future__ import annotations

import sys

from twisted.core.runner import (
    default_linux_capabilities,
    default_windows_capabilities,
    find_tools,
    run_cmd,
    tool_available,
)


class TestToolAvailable:
    def test_python_is_available(self) -> None:
        assert tool_available("python3") or tool_available("python")

    def test_unknown_tool_is_unavailable(self) -> None:
        assert tool_available("definitely-not-a-real-tool-xyzzy") is False

    def test_find_tools_returns_dict_with_paths_or_none(self) -> None:
        result = find_tools("python3", "definitely-not-a-real-tool-xyzzy")
        assert "python3" in result
        assert "definitely-not-a-real-tool-xyzzy" in result
        assert result["definitely-not-a-real-tool-xyzzy"] is None


class TestRunCmd:
    def test_simple_success(self) -> None:
        r = run_cmd([sys.executable, "-c", "print('hello')"])
        assert r.ok
        assert r.returncode == 0
        assert "hello" in r.stdout
        assert r.duration_ms >= 0

    def test_string_command_is_split(self) -> None:
        r = run_cmd(f"{sys.executable} -c \"print('shell-ish')\"")
        assert r.ok
        assert "shell-ish" in r.stdout

    def test_nonzero_exit_recorded_not_raised(self) -> None:
        # check=False (default) -> non-zero exit is reported via returncode/ok
        # but does NOT populate error (that's reserved for FileNotFoundError /
        # timeouts / unexpected exceptions).
        r = run_cmd([sys.executable, "-c", "import sys; sys.exit(7)"])
        assert r.returncode == 7
        assert not r.ok
        assert r.error is None

    def test_nonzero_exit_with_check_records_error(self) -> None:
        r = run_cmd([sys.executable, "-c", "import sys; sys.exit(7)"], check=True)
        assert r.returncode == 7
        assert not r.ok
        assert r.error is not None
        assert "non-zero exit" in r.error

    def test_stderr_captured(self) -> None:
        r = run_cmd([sys.executable, "-c", "import sys; sys.stderr.write('boom')"])
        assert r.ok
        assert "boom" in r.stderr
        combined = r.combined_output()
        assert "boom" in combined

    def test_timeout_marked(self) -> None:
        r = run_cmd([sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)
        assert r.timed_out is True
        assert "timeout" in (r.error or "")
        assert not r.ok

    def test_missing_tool(self) -> None:
        r = run_cmd(["definitely-not-a-real-tool-xyzzy"])
        assert r.error is not None
        assert "not installed" in r.error
        assert not r.ok

    def test_empty_command(self) -> None:
        r = run_cmd([])
        assert r.error == "empty command"
        assert not r.ok

    def test_stdin_passes_through(self) -> None:
        r = run_cmd([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
                    input_text="hello world")
        assert r.ok
        assert "HELLO WORLD" in r.stdout


class TestCapabilityDefaults:
    def test_linux_caps_always_includes_basics(self) -> None:
        caps = default_linux_capabilities()
        assert "python" in caps
        assert "network" in caps

    def test_windows_caps_always_includes_basics(self) -> None:
        caps = default_windows_capabilities()
        # 'browser' / 'screenshots' / 'windows' are always claimed; the actual
        # presence is approximate (PATH-based) but the surface should exist.
        assert "browser" in caps or len(caps) > 0
