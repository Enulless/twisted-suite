"""Tests for recon modules.

Network calls are mocked. Real-network tests live separately under the
'network' marker and are not run by default.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from twisted.core.scope import Scope
from twisted.modules.base import ModuleContext
from twisted.modules.recon import crtsh, dns_enum, headers_audit, http_probe, tls_audit, whois_lookup


def _ctx(work_dir: Path, **params) -> ModuleContext:
    return ModuleContext(
        engagement_id=1,
        step_id="bb.stage1.test",
        procedure="bb",
        stage="stage1",
        params=params,
        work_dir=work_dir,
        scope=None,
        timestamp=datetime(2026, 4, 25, 0, 30, 0),
        worker_id="test",
        worker_host="wsl",
    )


# ──────────────────────────── crt.sh ────────────────────────────


class TestCrtsh:
    def test_extract_subdomains_filters_by_suffix(self) -> None:
        rows = [
            {"name_value": "api.acme.example\nstaging.acme.example"},
            {"name_value": "*.dev.acme.example"},
            {"common_name": "acme.example"},
            {"name_value": "unrelated.com"},
            {"name_value": "API.ACME.EXAMPLE"},  # case
        ]
        found = crtsh.extract_subdomains(rows, "acme.example")
        assert "api.acme.example" in found
        assert "staging.acme.example" in found
        assert "dev.acme.example" in found
        assert "acme.example" in found
        assert "unrelated.com" not in found

    def test_run_writes_artifacts_and_returns_assets(self, tmp_path: Path) -> None:
        rows = [{"name_value": "api.acme.example\nstaging.acme.example"}]
        with patch.object(crtsh, "_query_crtsh", return_value=rows):
            result = crtsh.run(_ctx(tmp_path, domain="acme.example"))
        assert result.success
        assert len(result.artifacts) == 2
        assert any(p.suffix == ".json" for p in result.artifacts)
        assert any(p.suffix == ".txt" for p in result.artifacts)
        # Two assets in scope (no scope filter set)
        hosts = sorted(a.host for a in result.assets)
        assert hosts == ["api.acme.example", "staging.acme.example"]

    def test_run_honours_scope(self, tmp_path: Path) -> None:
        rows = [{"name_value": "api.acme.example\nbad.osp.acme.example"}]
        scope = Scope.from_lists(wildcards=["acme.example"], oos=[r".*\.osp\.acme\.example$"])
        ctx = _ctx(tmp_path, domain="acme.example")
        ctx.scope = scope
        with patch.object(crtsh, "_query_crtsh", return_value=rows):
            result = crtsh.run(ctx)
        hosts = [a.host for a in result.assets]
        assert "api.acme.example" in hosts
        assert "bad.osp.acme.example" not in hosts

    def test_run_missing_domain_param(self, tmp_path: Path) -> None:
        result = crtsh.run(_ctx(tmp_path))
        assert not result.success
        assert "missing required param" in (result.error or "")

    def test_run_handles_request_failure(self, tmp_path: Path) -> None:
        import requests as _requests

        def boom(*_a, **_kw):
            raise _requests.ConnectionError("DNS fail")

        with patch.object(crtsh, "_query_crtsh", side_effect=boom):
            result = crtsh.run(_ctx(tmp_path, domain="acme.example"))
        assert not result.success
        assert "request failed" in (result.error or "")


# ──────────────────────────── dns_enum ────────────────────────────


class TestDnsEnum:
    def test_run_uses_dig_when_present(self, tmp_path: Path) -> None:
        # Stub _dig to avoid actual network and dig binary requirements.
        with patch.object(dns_enum, "tool_available", return_value=True), \
             patch.object(dns_enum, "_dig", side_effect=lambda host, rtype, **_:
                          {"A": ["192.0.2.1"], "MX": ["10 mail.acme.example"]}.get(rtype, [])):
            result = dns_enum.run(_ctx(tmp_path, host="acme.example"))
        assert result.success
        json_path = next(p for p in result.artifacts if p.suffix == ".json")
        data = json.loads(json_path.read_text())
        assert data["records"]["A"] == ["192.0.2.1"]
        assert data["records"]["MX"] == ["10 mail.acme.example"]
        assert "2 records" in result.summary

    def test_missing_host_param(self, tmp_path: Path) -> None:
        with patch.object(dns_enum, "tool_available", return_value=True):
            result = dns_enum.run(_ctx(tmp_path))
        assert not result.success
        assert "missing required param" in (result.error or "")

    def test_no_dig_installed(self, tmp_path: Path) -> None:
        with patch.object(dns_enum, "tool_available", return_value=False):
            result = dns_enum.run(_ctx(tmp_path, host="acme.example"))
        assert not result.success
        assert "dig not installed" in (result.error or "")


# ──────────────────────────── whois ────────────────────────────


class TestWhois:
    def test_root_domain_extraction(self) -> None:
        assert whois_lookup._root_domain("api.staging.acme.example") == "acme.example"
        assert whois_lookup._root_domain("acme.example") == "acme.example"
        assert whois_lookup._root_domain("singleword") == "singleword"

    def test_run_with_stubbed_whois(self, tmp_path: Path) -> None:
        fake_output = (
            "Domain Name: ACME.EXAMPLE\n"
            "Registrar: Example Registrar\n"
            "Registry Expiry Date: 2030-04-24T00:00:00Z\n"
            "Name Server: NS1.EXAMPLE.COM\n"
            "Name Server: NS2.EXAMPLE.COM\n"
        )
        from twisted.core.runner import CommandResult
        result_mock = CommandResult(cmd=["whois"], returncode=0,
                                    stdout=fake_output, stderr="", duration_ms=10)
        with patch.object(whois_lookup, "tool_available", return_value=True), \
             patch.object(whois_lookup, "run_cmd", return_value=result_mock):
            result = whois_lookup.run(_ctx(tmp_path, domain="api.acme.example"))
        assert result.success
        assert "expiry=" in (result.summary or "")


# ──────────────────────────── http_probe ────────────────────────────


class _FakeResponse:
    def __init__(self, status: int, text: str = "", headers: dict[str, str] | None = None,
                 url: str = "", history: list | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.history = history or []


class TestHttpProbe:
    def test_probe_one_records_status_and_title(self) -> None:
        sess = MagicMock()
        sess.get.return_value = _FakeResponse(
            200, "<html><title>Hello</title></html>",
            headers={"Server": "nginx/1.20", "X-Powered-By": "PHP/8.1"},
        )
        info = http_probe.probe_one("acme.example", session=sess)
        assert info["status"] == 200
        assert info["title"] == "Hello"
        assert info["server"].startswith("nginx")
        assert any("X-Powered-By" in t for t in info["techs"])

    def test_run_filters_by_scope(self, tmp_path: Path) -> None:
        # Patch probe_one to skip real network
        with patch.object(http_probe, "probe_one",
                           return_value={"host": "api.acme.example", "status": 200,
                                         "title": "ok", "server": "nginx", "techs": [],
                                         "scheme_used": "https", "headers": {}, "redirect": None}):
            ctx = _ctx(tmp_path, hosts=["api.acme.example", "evil.com"])
            ctx.scope = Scope.from_lists(wildcards=["acme.example"])
            result = http_probe.run(ctx)
        assert result.success
        # Only api.acme.example survived scope filtering
        assert any(a.host == "api.acme.example" for a in result.assets)
        assert all(a.host != "evil.com" for a in result.assets)


# ──────────────────────────── headers_audit ────────────────────────────


class TestHeadersAudit:
    def test_audit_detects_missing_headers(self) -> None:
        sess = MagicMock()
        sess.get.return_value = _FakeResponse(
            200, "", headers={"Server": "nginx", "X-Frame-Options": "SAMEORIGIN"},
        )
        result = headers_audit.audit_headers("acme.example", session=sess)
        assert "X-Frame-Options" in result["present"]
        assert "Content-Security-Policy" in result["missing"]
        assert "Strict-Transport-Security" in result["missing"]
        assert result["cors_wildcard"] is False

    def test_audit_flags_cors_wildcard(self) -> None:
        sess = MagicMock()
        sess.get.return_value = _FakeResponse(
            200, "", headers={"Access-Control-Allow-Origin": "*"},
        )
        result = headers_audit.audit_headers("acme.example", session=sess)
        assert result["cors_wildcard"] is True

    def test_run_emits_finding_drafts(self, tmp_path: Path) -> None:
        sess = MagicMock()
        sess.get.return_value = _FakeResponse(
            200, "", headers={"Access-Control-Allow-Origin": "*"},
        )
        with patch("twisted.modules.recon.headers_audit.requests.Session", return_value=sess):
            result = headers_audit.run(_ctx(tmp_path, host="acme.example"))
        assert result.success
        titles = [f.title for f in result.findings]
        assert any("Missing Strict-Transport-Security" in t for t in titles)
        assert any("Wildcard CORS" in t for t in titles)


# ──────────────────────────── tls_audit ────────────────────────────


SAMPLE_CERT_TEXT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Apr 24 00:00:00 2026 GMT
            Not After : Jul 23 23:59:59 2026 GMT
        Subject: CN = acme.example
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:acme.example, DNS:www.acme.example
"""


class TestTlsAudit:
    def test_parse_cert_text_extracts_fields(self) -> None:
        parsed = tls_audit.parse_cert_text(SAMPLE_CERT_TEXT)
        assert parsed["subject"].startswith("CN = acme.example")
        assert parsed["issuer"].startswith("C = US")
        assert parsed["key_bits"] == 2048
        assert "acme.example" in parsed["san"]
        assert "www.acme.example" in parsed["san"]
        assert parsed["signature_algorithm"] == "sha256WithRSAEncryption"

    def test_run_with_stubbed_cert(self, tmp_path: Path) -> None:
        with patch.object(tls_audit, "tool_available", return_value=True), \
             patch.object(tls_audit, "fetch_cert_text", return_value=SAMPLE_CERT_TEXT):
            result = tls_audit.run(_ctx(tmp_path, host="acme.example"))
        assert result.success

    def test_run_flags_weak_key(self, tmp_path: Path) -> None:
        weak = SAMPLE_CERT_TEXT.replace("Public-Key: (2048 bit)", "Public-Key: (1024 bit)")
        with patch.object(tls_audit, "tool_available", return_value=True), \
             patch.object(tls_audit, "fetch_cert_text", return_value=weak):
            result = tls_audit.run(_ctx(tmp_path, host="acme.example"))
        titles = [f.title for f in result.findings]
        assert any("Weak TLS key strength (1024-bit)" in t for t in titles)

    def test_run_flags_expired_cert(self, tmp_path: Path) -> None:
        expired = SAMPLE_CERT_TEXT.replace(
            "Not After : Jul 23 23:59:59 2026 GMT",
            "Not After : Jan 23 23:59:59 2020 GMT",
        )
        with patch.object(tls_audit, "tool_available", return_value=True), \
             patch.object(tls_audit, "fetch_cert_text", return_value=expired):
            result = tls_audit.run(_ctx(tmp_path, host="acme.example"))
        titles = [f.title for f in result.findings]
        assert any("Expired TLS certificate" in t for t in titles)
