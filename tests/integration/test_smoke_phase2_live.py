"""Phase 2 live smoke tests — invoke real ``nmap``, ``dig``, ``openssl``
against canonical cooperative targets so we can catch the bugs that the
mock-only unit and integration tests can't surface.

These tests are SKIPPED by default. Opt in with::

    pytest -m network                       # all network-dependent tests
    pytest tests/integration/test_smoke_phase2_live.py -m network

Each test additionally skips itself if (a) outbound networking is
unavailable, or (b) the underlying tool isn't installed on PATH, so the
file is safe to leave in the suite even on machines without these tools.

Targets:
- ``scanme.nmap.org`` — explicitly authorised by the Nmap Project for
  scanning practice (see https://nmap.org/book/legal-issues.html). Has
  ports 22/ssh and 80/http reliably open.
- ``example.com`` — IANA-reserved test domain with a stable, modern
  HTTPS certificate. Used for the TLS audit because scanme.nmap.org
  doesn't expose 443.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path

import pytest

from twisted.core.runner import tool_available
from twisted.modules.base import ModuleContext
from twisted.modules.recon import dns_enum, nmap_scan, tls_audit

NMAP_TARGET = "scanme.nmap.org"
TLS_TARGET = "example.com"


def _has_internet() -> bool:
    """Quick TCP probe to a well-known anycast resolver."""
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _require_internet() -> None:
    if not _has_internet():
        pytest.skip("no outbound network available", allow_module_level=True)


def _ctx(tmp_path: Path, step_id: str, params: dict) -> ModuleContext:
    work = tmp_path / step_id.replace(".", "_")
    work.mkdir(parents=True, exist_ok=True)
    return ModuleContext(
        engagement_id=1,
        step_id=step_id,
        procedure="bb",
        stage="stage_smoke",
        params=params,
        work_dir=work,
        scope=None,
        timestamp=datetime.now(),
        worker_id="smoke-test",
        worker_host="wsl",
    )


@pytest.mark.network
@pytest.mark.integration
def test_dns_enum_resolves_scanme(tmp_path: Path) -> None:
    """`dig` against scanme.nmap.org returns A + NS records and the
    module produces both .json and .txt artifacts."""
    if not tool_available("dig"):
        pytest.skip("dig not installed (apt install dnsutils)")

    ctx = _ctx(
        tmp_path,
        "bb.stage1.dns_enum",
        {"host": NMAP_TARGET, "record_types": ["A", "NS"]},
    )
    result = dns_enum.run(ctx)
    assert result.success, f"dns_enum failed: {result.error}"

    suffixes = {p.suffix for p in result.artifacts}
    assert ".json" in suffixes, f"missing .json artifact, got {suffixes}"
    assert ".txt" in suffixes, f"missing .txt artifact, got {suffixes}"

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    payload = json.loads(json_path.read_text())
    assert payload["host"] == NMAP_TARGET
    assert payload["records"], "no DNS records returned for scanme.nmap.org"
    # scanme.nmap.org reliably has at least one A record
    assert payload["records"].get("A"), "no A record for scanme.nmap.org"
    assert result.extra["record_count"] >= 1


@pytest.mark.network
@pytest.mark.integration
def test_nmap_scan_top_ports_scanme(tmp_path: Path) -> None:
    """`nmap -sV` against scanme.nmap.org parses real output into a
    structured port list with at least one open port."""
    if not tool_available("nmap"):
        pytest.skip("nmap not installed (apt install nmap)")

    ctx = _ctx(
        tmp_path,
        "bb.stage4.nmap_top",
        {"hosts": [NMAP_TARGET]},
    )
    result = nmap_scan.scan_top_ports(ctx)
    assert result.success, f"nmap_scan failed: {result.error}"

    assert result.extra["hosts_scanned"] == 1
    # scanme.nmap.org advertises 22/ssh and 80/http as open per Nmap docs
    assert result.extra["open_port_count"] >= 1, (
        "expected at least one open port on scanme.nmap.org"
    )

    # AssetUpdate row created for the scanned host
    hosts_in_assets = {a.host for a in result.assets}
    # nmap may rewrite the target to its canonical form (scanme.nmap.org or
    # 45.33.32.156); accept either as long as one row was emitted
    assert hosts_in_assets, "nmap_scan produced no asset rows"

    # JSON artifact is well-formed and contains structured port info
    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    parsed = json.loads(json_path.read_text())
    assert parsed, "nmap JSON artifact is empty"
    assert any(parsed.values()), "no host has open ports in parsed output"

    # Sanity: at least one open port has a port number, proto, and service field
    ports = next(plist for plist in parsed.values() if plist)
    sample = ports[0]
    assert {"port", "proto", "service"} <= set(sample.keys())


@pytest.mark.network
@pytest.mark.integration
def test_tls_audit_example_com(tmp_path: Path) -> None:
    """`openssl s_client` + `x509 -text` against example.com produces a
    parsed cert with subject/issuer/validity/key_bits, and no
    expired-cert finding is raised."""
    if not tool_available("openssl"):
        pytest.skip("openssl not installed")

    ctx = _ctx(
        tmp_path,
        "bb.stage4.tls_audit",
        {"host": TLS_TARGET, "timeout": 15},
    )
    result = tls_audit.run(ctx)
    assert result.success, f"tls_audit failed: {result.error}"

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    audits = json.loads(json_path.read_text())
    assert len(audits) == 1
    cert = audits[0]
    assert cert["host"] == TLS_TARGET
    assert cert["subject"], "openssl returned no Subject"
    assert cert["issuer"], "openssl returned no Issuer"
    assert cert["not_before"], "openssl returned no Not Before"
    assert cert["not_after"], "openssl returned no Not After"
    assert cert["key_bits"] is not None, "openssl returned no Public-Key bits"
    assert cert["key_algorithm"] in {"rsa", "ec", "ed25519", "ed448"}, (
        f"unexpected key_algorithm={cert['key_algorithm']!r}"
    )

    # The audit must agree with the algorithm-aware weak-key heuristic:
    # a real cert from a public CA on a high-traffic domain should never
    # be flagged as weak by definition.
    assert not tls_audit.is_weak_key(cert["key_algorithm"], cert["key_bits"]), (
        f"smoke target {TLS_TARGET} flagged as weak: "
        f"{cert['key_algorithm']} {cert['key_bits']}-bit"
    )

    weak_titles = [f.title for f in result.findings if "Weak TLS key" in (f.title or "")]
    assert not weak_titles, (
        f"unexpected weak-key finding for {TLS_TARGET}: {weak_titles}"
    )

    expired_titles = [f.title for f in result.findings if "Expired" in (f.title or "")]
    assert not expired_titles, (
        f"unexpected expired-cert finding for {TLS_TARGET}: {expired_titles}"
    )
