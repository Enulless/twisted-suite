"""Unit tests for Phase 2 recon + report modules.

External tools and HTTP calls are mocked. The runtime contract from
Phase 1 (`ModuleResult`) is enforced.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from twisted.modules.base import ModuleContext, ModuleResult
from twisted.modules.recon import (
    aggregators,
    email_security,
    nikto_scan,
    nmap_scan,
    nvd_lookup,
    risk_scoring,
)


def _ctx(work_dir: Path, **params) -> ModuleContext:
    return ModuleContext(
        engagement_id=1, step_id="bb.test", procedure="bb",
        stage="stage1", params=params, work_dir=work_dir,
        scope=None, timestamp=datetime(2026, 4, 25, 1, 0, 0),
        worker_id="t", worker_host="wsl",
    )


# ──────────────────────────── email_security ────────────────────────────


class TestEmailSecurity:
    def test_missing_records_emit_findings(self, tmp_path: Path) -> None:
        with patch.object(email_security, "tool_available", return_value=True), \
             patch.object(email_security, "_txt", return_value=[]):
            r = email_security.run(_ctx(tmp_path, domain="acme.example"))
        assert r.success
        titles = [f.title for f in r.findings]
        assert any("Missing SPF" in t for t in titles)
        assert any("Missing DMARC" in t for t in titles)
        assert any("DKIM" in t for t in titles)

    def test_strict_records_no_findings(self, tmp_path: Path) -> None:
        responses = {
            "acme.example": ['v=spf1 include:_spf.google.com -all'],
            "_dmarc.acme.example": ['v=DMARC1; p=reject; rua=mailto:dmarc@acme.example'],
            "default._domainkey.acme.example": ['v=DKIM1; k=rsa; p=ABC'],
        }
        with patch.object(email_security, "tool_available", return_value=True), \
             patch.object(email_security, "_txt",
                          side_effect=lambda host, **_: responses.get(host, [])):
            r = email_security.run(_ctx(tmp_path, domain="acme.example"))
        assert r.success
        # No findings — strict policy + DKIM present
        assert r.findings == []

    def test_dmarc_p_none_warns(self, tmp_path: Path) -> None:
        responses = {
            "acme.example": ['v=spf1 -all'],
            "_dmarc.acme.example": ['v=DMARC1; p=none'],
            "default._domainkey.acme.example": ['v=DKIM1; p=ABC'],
        }
        with patch.object(email_security, "tool_available", return_value=True), \
             patch.object(email_security, "_txt",
                          side_effect=lambda host, **_: responses.get(host, [])):
            r = email_security.run(_ctx(tmp_path, domain="acme.example"))
        titles = [f.title for f in r.findings]
        assert any("Weak DMARC policy (p=none)" in t for t in titles)

    def test_no_dig_fails_gracefully(self, tmp_path: Path) -> None:
        with patch.object(email_security, "tool_available", return_value=False):
            r = email_security.run(_ctx(tmp_path, domain="acme.example"))
        assert not r.success
        assert "dig not installed" in (r.error or "")


# ──────────────────────────── aggregators ────────────────────────────


class TestAggregators:
    def test_subfinder_ok(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        cmd_result = CommandResult(cmd=[], returncode=0,
                                   stdout="api.acme.example\nstaging.acme.example\nunrelated.com",
                                   stderr="", duration_ms=1)
        with patch.object(aggregators, "tool_available", return_value=True), \
             patch.object(aggregators, "run_cmd", return_value=cmd_result):
            r = aggregators.subfinder(_ctx(tmp_path, domain="acme.example"))
        assert r.success
        hosts = sorted(a.host for a in r.assets)
        assert hosts == ["api.acme.example", "staging.acme.example"]
        # All assets tagged with the right source
        assert all(a.source == "subfinder" for a in r.assets)

    def test_assetfinder_missing_tool(self, tmp_path: Path) -> None:
        with patch.object(aggregators, "tool_available", return_value=False):
            r = aggregators.assetfinder(_ctx(tmp_path, domain="acme.example"))
        assert not r.success
        assert "assetfinder not installed" in (r.error or "")


# ──────────────────────────── nmap_scan ────────────────────────────


SAMPLE_NMAP = """
Starting Nmap 7.94
Nmap scan report for api.acme.example (203.0.113.10)
Host is up (0.012s latency).
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http      nginx 1.20.1
443/tcp  open  ssl/http  nginx 1.20.1

Nmap done: 1 IP address (1 host up) scanned in 1.50 seconds
"""


class TestNmapScan:
    def test_parse_open_ports(self) -> None:
        parsed = nmap_scan.parse_nmap_text(SAMPLE_NMAP)
        assert "api.acme.example" in parsed
        ports = parsed["api.acme.example"]
        port_nums = sorted(p["port"] for p in ports)
        assert port_nums == [22, 80, 443]
        ssh = next(p for p in ports if p["port"] == 22)
        assert ssh["service"] == "ssh"
        assert "OpenSSH 7.4" in ssh["version"]

    def test_run_when_nmap_missing(self, tmp_path: Path) -> None:
        with patch.object(nmap_scan, "tool_available", return_value=False):
            r = nmap_scan.scan_top_ports(_ctx(tmp_path, hosts=["api.acme.example"]))
        assert not r.success
        assert "nmap not installed" in (r.error or "")

    def test_run_with_stubbed_nmap_writes_artifacts(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        cmd_result = CommandResult(cmd=[], returncode=0, stdout=SAMPLE_NMAP,
                                   stderr="", duration_ms=1)
        with patch.object(nmap_scan, "tool_available", return_value=True), \
             patch.object(nmap_scan, "run_cmd", return_value=cmd_result):
            r = nmap_scan.scan_top_ports(_ctx(tmp_path, hosts=["api.acme.example"]))
        assert r.success
        # The asset is reported with open ports recorded
        assert any(a.host == "api.acme.example" for a in r.assets)


# ──────────────────────────── nikto_scan ────────────────────────────


SAMPLE_NIKTO = """- Nikto v2.5.0
+ Target IP:          203.0.113.10
+ Server: nginx/1.20.1
+ /admin/: This is the admin login page
+ The X-XSS-Protection header is not defined.
+ /backup/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ CVE-2023-12345: vulnerable apache mod
+ 7916 requests, 2 errors
"""


class TestNikto:
    def test_parse(self) -> None:
        items = nikto_scan.parse(SAMPLE_NIKTO)
        # Should skip the metadata lines like "Target IP:" / "Server:"
        messages = [it["message"] for it in items]
        assert any("/admin/" in m for m in messages)
        assert any("Directory indexing" in m for m in messages)
        assert any("vulnerable apache mod" in m for m in messages)
        # CVE row picked up
        cve_items = [it for it in items if it["cves"]]
        assert cve_items
        assert cve_items[0]["severity"] == "high"

    def test_run_when_missing(self, tmp_path: Path) -> None:
        with patch.object(nikto_scan, "tool_available", return_value=False):
            r = nikto_scan.run(_ctx(tmp_path, hosts=["acme.example"]))
        assert not r.success


# ──────────────────────────── nvd_lookup ────────────────────────────


SAMPLE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                },
                "descriptions": [{"lang": "en", "value": "Test critical vuln"}],
                "references": [{"url": "https://example.com/advisory"}],
            },
        },
    ],
}


class TestNvdLookup:
    def test_flatten(self) -> None:
        flat = nvd_lookup._flatten(SAMPLE_NVD["vulnerabilities"][0])
        assert flat["cve_id"] == "CVE-2023-99999"
        assert flat["cvss_score"] == 9.8
        assert flat["severity"] == "CRITICAL"
        assert flat["references"] == ["https://example.com/advisory"]

    def test_run_no_assets(self, tmp_path: Path) -> None:
        fake_client = MagicMock()
        fake_client.get.return_value = []
        with patch.object(nvd_lookup, "get_client", return_value=fake_client):
            r = nvd_lookup.run(_ctx(tmp_path, engagement_id=1))
        assert r.success
        assert "no assets" in (r.summary or "")

    def test_run_no_techs(self, tmp_path: Path) -> None:
        fake_client = MagicMock()
        fake_client.get.return_value = [{"id": 1, "host": "x", "techs": []}]
        with patch.object(nvd_lookup, "get_client", return_value=fake_client):
            r = nvd_lookup.run(_ctx(tmp_path, engagement_id=1))
        assert r.success
        assert "no asset technologies" in (r.summary or "")

    def test_run_attaches_cves(self, tmp_path: Path) -> None:
        fake_client = MagicMock()
        fake_client.get.return_value = [
            {"id": 1, "host": "api.acme.example", "techs": [{"name": "Apache", "version": "2.4.41"}]},
        ]
        with patch.object(nvd_lookup, "get_client", return_value=fake_client), \
             patch.object(nvd_lookup, "_query_nvd",
                          return_value=SAMPLE_NVD["vulnerabilities"]):
            r = nvd_lookup.run(_ctx(tmp_path, engagement_id=1, rate_sleep=0))
        assert r.success
        # post should have been called with CVE list for asset 1
        post_calls = [c for c in fake_client.post.call_args_list]
        assert post_calls
        assert "/cves" in post_calls[0].args[0]


# ──────────────────────────── risk_scoring ────────────────────────────


class TestRiskScoring:
    def test_score_low_for_clean_asset(self) -> None:
        asset = {"id": 1, "host": "api.acme.example", "env_type": "production",
                 "techs": [], "cves": [], "ports": []}
        scored = risk_scoring.score_asset(asset)
        assert scored["total"] == 0
        assert risk_scoring.tier(scored["total"]) == "low"

    def test_score_high_for_db_exposed_dev(self) -> None:
        asset = {"id": 2, "host": "dev-db.acme.example", "env_type": "dev",
                 "techs": [{"name": "MySQL", "version": "5.5 (2010)"}],
                 "cves": [{"cvss_score": 9.5}, {"cvss_score": 7.0}],
                 "ports": [{"port": 3306, "proto": "tcp"}, {"port": 22, "proto": "tcp"}]}
        scored = risk_scoring.score_asset(asset)
        assert scored["total"] >= 13  # critical or high
        tier = risk_scoring.tier(scored["total"])
        assert tier in ("high", "critical")
        factors = {b["factor"] for b in scored["breakdown"]}
        assert "known_cves" in factors
        assert "port_exposure" in factors
        assert "env_dev_staging" in factors

    @pytest.mark.parametrize(
        ("total", "expected"),
        [(0, "low"), (5, "low"), (6, "medium"), (12, "medium"),
         (13, "high"), (20, "high"), (21, "critical"), (50, "critical")],
    )
    def test_tier_buckets(self, total: int, expected: str) -> None:
        assert risk_scoring.tier(total) == expected

    def test_run_posts_per_asset(self, tmp_path: Path) -> None:
        fake_client = MagicMock()
        fake_client.get.return_value = [
            {"id": 1, "host": "a", "env_type": "production", "techs": [], "cves": [], "ports": []},
            {"id": 2, "host": "b", "env_type": "dev", "techs": [], "cves": [], "ports": []},
        ]
        with patch.object(risk_scoring, "get_client", return_value=fake_client):
            r = risk_scoring.run(_ctx(tmp_path, engagement_id=1))
        assert r.success
        # Two POSTs, one per asset
        post_paths = [c.args[0] for c in fake_client.post.call_args_list]
        assert len([p for p in post_paths if "/risk" in p]) == 2
        assert r.extra["scored"] == 2
