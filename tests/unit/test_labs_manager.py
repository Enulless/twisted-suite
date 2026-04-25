"""Unit tests for the lab manager module.

Mocks subprocess so we can verify command construction without
actually invoking docker.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from twisted.labs import manager as lm


class TestCatalogue:
    def test_all_four_labs_registered(self) -> None:
        ids = set(lm.LAB_CATALOGUE)
        assert ids == {"dvwa", "juice_shop", "wordpress", "metasploitable"}

    def test_get_lab_returns_spec(self) -> None:
        spec = lm.get_lab("dvwa")
        assert spec.id == "dvwa"
        assert spec.project_name == "twisted_dvwa"
        assert spec.target_url.startswith("http://127.0.0.1:")

    def test_get_lab_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            lm.get_lab("not-a-lab")

    def test_target_url_honours_env_override(self,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
        spec = lm.get_lab("dvwa")
        monkeypatch.setenv(spec.port_env, "29999")
        assert "29999" in spec.target_url

    def test_lab_for_step_finds_match(self) -> None:
        spec = lm.lab_for_step("wp_stress.phase2.escalating")
        assert spec is not None and spec.id == "wordpress"
        assert lm.lab_for_step("not.a.real.step") is None

    def test_compose_files_exist_on_disk(self) -> None:
        for spec in lm.LAB_CATALOGUE.values():
            path = lm.REPO_ROOT / spec.compose_relpath
            assert path.is_file(), f"missing compose file: {path}"


class TestPsParsing:
    def test_json_lines_format(self) -> None:
        out = (
            '{"Name":"twisted_dvwa-dvwa-1","Service":"dvwa","State":"running"}\n'
            '{"Name":"twisted_dvwa-db-1","Service":"db","State":"exited"}\n'
        )
        services = lm._parse_ps_output(out)
        assert services["twisted_dvwa-dvwa-1"] == "running"
        assert services["twisted_dvwa-db-1"] == "exited"

    def test_legacy_text_format(self) -> None:
        out = (
            "NAME           STATE\n"
            "twisted_x-1    Up 5 minutes\n"
            "twisted_x-2    Exit 0\n"
        )
        services = lm._parse_ps_output(out)
        assert services.get("twisted_x-1") == "up"
        assert services.get("twisted_x-2") == "exited"

    def test_empty_output(self) -> None:
        assert lm._parse_ps_output("") == {}


class TestOperationsWhenDockerMissing:
    def test_status_returns_unknown(self,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(lm, "docker_available", lambda: False)
        st = lm.lab_status(lm.get_lab("dvwa"))
        assert st.state == lm.LabState.UNKNOWN

    def test_up_returns_unavailable(self,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(lm, "docker_available", lambda: False)
        r = lm.lab_up(lm.get_lab("dvwa"))
        assert r.success is False
        assert r.available is False
        assert "docker" in (r.error or "").lower()

    def test_down_returns_unavailable(self,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(lm, "docker_available", lambda: False)
        r = lm.take_lab_down(lm.get_lab("dvwa"))
        assert r.success is False
        assert r.available is False

    def test_logs_returns_unavailable(self,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(lm, "docker_available", lambda: False)
        r = lm.lab_logs(lm.get_lab("dvwa"))
        assert r.success is False
        assert r.available is False


class TestOperationsWithDocker:
    def test_up_invokes_compose_correctly(self,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        def fake_run(cmd, capture_output, text, timeout, env):
            captured["cmd"] = cmd
            captured["env"] = {k: v for k, v in (env or {}).items()
                                if k.endswith("_PORT")}
            r = MagicMock()
            r.returncode = 0
            r.stdout = "Container twisted_dvwa-dvwa-1 Started\n"
            r.stderr = ""
            return r

        monkeypatch.setattr(lm, "_docker_compose_cmd",
                             lambda: ["docker", "compose"])
        monkeypatch.setattr(lm.subprocess, "run", fake_run)
        # Avoid the second compose call (status check) hitting subprocess
        monkeypatch.setattr(lm, "lab_status",
                             lambda spec: lm.LabStatus(spec=spec,
                                                        state=lm.LabState.UP,
                                                        target_url=spec.target_url))
        result = lm.lab_up(lm.get_lab("dvwa"), port=29999)
        assert result.success is True
        assert result.state == lm.LabState.UP
        # Verifies the compose command shape
        cmd = captured["cmd"]
        assert "docker" in cmd[0]
        assert "compose" in cmd[1]
        assert "-p" in cmd
        assert "twisted_dvwa" in cmd
        assert "-f" in cmd
        assert "up" in cmd and "-d" in cmd
        # Port forwarded via env var
        assert captured["env"].get("DVWA_PORT") == "29999"
