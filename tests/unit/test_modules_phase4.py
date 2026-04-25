"""Phase 4 — WiFi modules unit tests.

All shell-out and OS-level calls are mocked. WiFi tooling cannot run
in WSL2 by default, so these tests prove the modules behave correctly
when their tools are present, missing, or running on a hostile host.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from twisted.modules.base import ModuleContext
from twisted.modules.wifi import (
    airodump,
    handshake,
    hashcat_run,
    monitor,
    post_exploit,
    preflight,
    wps,
)


def _ctx(work_dir: Path, **params) -> ModuleContext:
    return ModuleContext(
        engagement_id=1, step_id="wifi.test", procedure="wifi",
        stage="phase1", params=params, work_dir=work_dir, scope=None,
        timestamp=datetime(2026, 4, 25, 1, 0, 0), worker_id="t", worker_host="wsl",
    )


# ──────────────────────────── preflight ────────────────────────────


class TestPreflight:
    def test_blocks_in_wsl_without_usbipd(self, tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TWISTED_WIFI_USBIPD", raising=False)
        with patch.object(preflight, "is_wsl", return_value=True), \
             patch.object(preflight, "list_wifi_interfaces", return_value=["wlan0"]), \
             patch.object(preflight, "supports_monitor", return_value=True), \
             patch.object(preflight, "is_root", return_value=True):
            r = preflight.run(_ctx(tmp_path))
        assert not r.success
        assert "WSL2 detected" in (r.error or "")

    def test_passes_in_wsl_with_usbipd_acknowledged(self, tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWISTED_WIFI_USBIPD", "1")
        with patch.object(preflight, "is_wsl", return_value=True), \
             patch.object(preflight, "list_wifi_interfaces", return_value=["wlan0"]), \
             patch.object(preflight, "supports_monitor", return_value=True), \
             patch.object(preflight, "is_root", return_value=True):
            r = preflight.run(_ctx(tmp_path))
        assert r.success

    def test_blocks_when_no_interfaces(self, tmp_path: Path,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TWISTED_WIFI_USBIPD", raising=False)
        with patch.object(preflight, "is_wsl", return_value=False), \
             patch.object(preflight, "list_wifi_interfaces", return_value=[]), \
             patch.object(preflight, "is_root", return_value=True):
            r = preflight.run(_ctx(tmp_path))
        assert not r.success
        assert "no wireless interfaces" in (r.error or "")

    def test_blocks_when_not_root(self, tmp_path: Path,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TWISTED_WIFI_USBIPD", raising=False)
        with patch.object(preflight, "is_wsl", return_value=False), \
             patch.object(preflight, "list_wifi_interfaces", return_value=["wlan0"]), \
             patch.object(preflight, "supports_monitor", return_value=True), \
             patch.object(preflight, "is_root", return_value=False):
            r = preflight.run(_ctx(tmp_path))
        assert not r.success
        assert "root" in (r.error or "").lower()


# ──────────────────────────── monitor ────────────────────────────


class TestMonitor:
    def test_enable_when_missing(self, tmp_path: Path) -> None:
        with patch.object(monitor, "tool_available", return_value=False):
            r = monitor.enable(_ctx(tmp_path, interface="wlan0"))
        assert not r.success

    def test_enable_with_stubbed_airmon(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        good = CommandResult(cmd=[], returncode=0,
                             stdout="monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon",
                             stderr="", duration_ms=1)
        with patch.object(monitor, "tool_available", return_value=True), \
             patch.object(monitor, "run_cmd", return_value=good):
            r = monitor.enable(_ctx(tmp_path, interface="wlan0"))
        assert r.success
        assert "wlan0mon" in r.summary


# ──────────────────────────── airodump ────────────────────────────


SAMPLE_AIRODUMP_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:11:22:33, 2026-04-25 01:00:00, 2026-04-25 01:01:00,  1, 130, WPA2 ,CCMP ,PSK ,-50,    100,        0,   0.   0.   0.   0,   8,    HomeWifi,
DD:EE:FF:44:55:66, 2026-04-25 01:00:00, 2026-04-25 01:01:00,  6, 130, WPA3 ,CCMP ,SAE ,-70,    100,        0,   0.   0.   0.   0,   7,    NextWifi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs

11:22:33:44:55:66, 2026-04-25 01:00:00, 2026-04-25 01:01:00, -55, 50, AA:BB:CC:11:22:33, HomeWifi
"""


class TestAirodump:
    def test_parse_csv(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "scan-01.csv"
        csv_path.write_text(SAMPLE_AIRODUMP_CSV)
        parsed = airodump.parse_airodump_csv(csv_path)
        assert len(parsed["aps"]) == 2
        assert parsed["aps"][0]["essid"] == "HomeWifi"
        assert parsed["aps"][1]["privacy"].strip().startswith("WPA3")
        assert len(parsed["clients"]) == 1


# ──────────────────────────── handshake ────────────────────────────


class TestHandshake:
    def test_missing_params(self, tmp_path: Path) -> None:
        r = handshake.capture(_ctx(tmp_path, interface="wlan0mon"))
        assert not r.success

    def test_missing_tool(self, tmp_path: Path) -> None:
        with patch.object(handshake, "tool_available", return_value=False):
            r = handshake.capture(_ctx(tmp_path, interface="wlan0mon",
                                        bssid="AA:BB:CC:11:22:33", channel=1))
        assert not r.success


# ──────────────────────────── hashcat_run ────────────────────────────


class TestHashcat:
    def test_missing_pcap(self, tmp_path: Path) -> None:
        r = hashcat_run.run(_ctx(tmp_path, pcap_path=str(tmp_path / "missing.cap")))
        assert not r.success
        assert "missing or file not present" in (r.error or "")

    def test_missing_hashcat(self, tmp_path: Path) -> None:
        pcap = tmp_path / "x.cap"
        pcap.write_bytes(b"FAKE")
        with patch.object(hashcat_run, "tool_available",
                           side_effect=lambda name: name == "hcxpcapngtool"):
            r = hashcat_run.run(_ctx(tmp_path, pcap_path=str(pcap),
                                      wordlist=str(pcap)))
        assert not r.success


# ──────────────────────────── wps ────────────────────────────


class TestWPS:
    def test_invalid_tool(self, tmp_path: Path) -> None:
        r = wps.attack(_ctx(tmp_path, interface="wlan0mon",
                             bssid="AA:BB:CC:11:22:33", channel=1, tool="hydra"))
        assert not r.success
        assert "tool must be" in (r.error or "")

    def test_missing_tool(self, tmp_path: Path) -> None:
        with patch.object(wps, "tool_available", return_value=False):
            r = wps.attack(_ctx(tmp_path, interface="wlan0mon",
                                 bssid="AA:BB:CC:11:22:33", channel=1, tool="reaver"))
        assert not r.success


# ──────────────────────────── post_exploit ────────────────────────────


class TestPostExploit:
    def test_gateway_discovery_parses_output(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        addr_json = '[{"ifname":"wlan0","addr_info":[{"family":"inet","local":"10.0.0.5","prefixlen":24}]}]'
        route_json = '[{"dst":"default","gateway":"10.0.0.1","dev":"wlan0"}]'
        resolv = "nameserver 10.0.0.1\nnameserver 1.1.1.1\n"

        def _stub(cmd, **_):
            joined = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "addr" in joined:
                return CommandResult(cmd=cmd, returncode=0, stdout=addr_json, stderr="", duration_ms=1)
            if "route" in joined:
                return CommandResult(cmd=cmd, returncode=0, stdout=route_json, stderr="", duration_ms=1)
            if "resolv" in joined:
                return CommandResult(cmd=cmd, returncode=0, stdout=resolv, stderr="", duration_ms=1)
            return CommandResult(cmd=cmd, returncode=0, stdout="", stderr="", duration_ms=1)

        with patch.object(post_exploit, "run_cmd", side_effect=_stub):
            r = post_exploit.gateway_discovery(_ctx(tmp_path))
        assert r.success
        assert r.extra["gateway"] == "10.0.0.1"
        assert "1.1.1.1" in r.extra["nameservers"]

    def test_credential_reuse_missing_tool(self, tmp_path: Path) -> None:
        with patch.object(post_exploit, "tool_available", return_value=False):
            r = post_exploit.credential_reuse(
                _ctx(tmp_path, subnet="10.0.0.0/24",
                     credentials=[{"user": "admin", "password": "pw"}])
            )
        assert not r.success
