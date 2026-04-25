"""Phase 2 live smoke tests — round 2.

Covers the modules left over from ``test_smoke_phase2_live.py``:

- ``http_probe``        — real HTTPS GET via requests
- ``headers_audit``     — security-header presence/absence check
- ``whois_lookup``      — `whois` binary against an IANA-managed domain
- ``nikto_scan``        — `nikto` binary (slow: budget several minutes)
- ``nvd_lookup``        — direct NVD API call (no engine roundtrip)

All tests are SKIPPED by default and require ``-m network`` to opt in.
Each test additionally skips itself if outbound networking is missing or
the underlying binary isn't installed, so the file is safe to keep in
the suite even on minimal dev hosts.

Cooperative targets:
- ``example.com`` — IANA-reserved test domain, stable HTTPS, polite to
  scan (low traffic, returns from a public CDN).
- ``services.nvd.nist.gov`` — public NIST API; rate-limited to ~5 req
  per 30 s without an API key, which is fine for a single smoke call.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime
from pathlib import Path

import pytest

from twisted.core.runner import tool_available
from twisted.modules.base import ModuleContext
from twisted.modules.recon import (
    headers_audit,
    http_probe,
    nikto_scan,
    nvd_lookup,
    whois_lookup,
)

HTTP_TARGET = "example.com"
WHOIS_TARGET = "example.com"
NIKTO_TARGET = "example.com"
NVD_KEYWORD = "log4j"


def _has_internet() -> bool:
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


# ──────────────────────────── http_probe ────────────────────────────


@pytest.mark.network
@pytest.mark.integration
def test_http_probe_example_com(tmp_path: Path) -> None:
    """`http_probe.run` against example.com returns a populated result
    with a 200 status, a parsed <title>, and a server header."""
    ctx = _ctx(
        tmp_path,
        "bb.stage2.http_probe",
        {"hosts": [HTTP_TARGET], "timeout": 15},
    )
    result = http_probe.run(ctx)
    assert result.success, result.error

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    payload = json.loads(json_path.read_text())
    assert len(payload) == 1
    info = payload[0]

    assert info["host"] == HTTP_TARGET
    assert info["scheme_used"] == "https", f"expected https, got {info['scheme_used']!r}"
    assert info["status"] == 200, f"unexpected status {info['status']}"
    assert info["title"], "no <title> parsed from example.com"
    assert "Example Domain" in info["title"], f"unexpected title: {info['title']!r}"
    # `requests` always returns a Server header through example.com's CDN
    # (even if empty string, the key exists in headers); confirm headers
    # captured at all.
    assert info["headers"], "headers dict is empty"

    # Asset row emitted because status is non-None
    assert any(a.host == HTTP_TARGET for a in result.assets)


# ──────────────────────────── headers_audit ────────────────────────────


@pytest.mark.network
@pytest.mark.integration
def test_headers_audit_example_com(tmp_path: Path) -> None:
    """`headers_audit.run` produces a parseable audit + at least one
    finding draft for a target that's missing several modern security
    headers (example.com historically has zero)."""
    ctx = _ctx(
        tmp_path,
        "bb.stage3.headers_audit",
        {"hosts": [HTTP_TARGET], "timeout": 15},
    )
    result = headers_audit.run(ctx)
    assert result.success, result.error

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    audits = json.loads(json_path.read_text())
    assert len(audits) == 1
    audit = audits[0]
    assert audit["host"] == HTTP_TARGET
    assert "error" not in audit, f"audit reported error: {audit.get('error')}"
    assert audit["status"] == 200
    assert isinstance(audit["present"], dict)
    assert isinstance(audit["missing"], list)

    # The number of findings must equal the number of guidance-mapped
    # missing headers, plus 1 if CORS wildcard is present.
    expected_findings = sum(
        1 for h in audit["missing"] if h in headers_audit.HEADER_GUIDANCE
    ) + (1 if audit.get("cors_wildcard") else 0)
    assert len(result.findings) == expected_findings, (
        f"finding count {len(result.findings)} != expected {expected_findings} "
        f"(missing={audit['missing']}, cors_wildcard={audit.get('cors_wildcard')})"
    )

    # Every finding must reference the target host
    for f in result.findings:
        assert HTTP_TARGET in (f.affected_component or ""), f.title


# ──────────────────────────── whois ────────────────────────────


@pytest.mark.network
@pytest.mark.integration
def test_whois_lookup_example_com(tmp_path: Path) -> None:
    """`whois example.com` returns a populated parsed dict including the
    canonical IANA fields (registrar/expiry/etc)."""
    if not tool_available("whois"):
        pytest.skip("whois not installed (apt install whois)")

    ctx = _ctx(
        tmp_path,
        "bb.stage1.whois",
        {"host": WHOIS_TARGET, "timeout": 20},
    )
    result = whois_lookup.run(ctx)
    assert result.success, result.error

    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    payload = json.loads(json_path.read_text())
    assert payload["domain"] == WHOIS_TARGET
    parsed = payload["parsed"]
    assert isinstance(parsed, dict) and parsed, "whois parser returned empty dict"

    # example.com is IANA-managed and always exposes some canonical keys.
    # Be lenient: the registry varies the casing and exact label slightly.
    keys_lower = set(parsed.keys())
    canonical_keys = {
        "domain name",
        "registrar",
        "registry expiry date",
        "expiration date",
        "name server",
        "creation date",
        "updated date",
    }
    overlap = keys_lower & canonical_keys
    assert overlap, (
        f"none of the canonical whois keys present, got keys: {sorted(keys_lower)}"
    )

    # The .txt artifact is the raw whois output and must not be empty
    raw_path = next(p for p in result.artifacts if p.suffix == ".txt")
    assert raw_path.read_text().strip(), "raw whois artifact is empty"


# ──────────────────────────── nikto ────────────────────────────


@pytest.mark.network
@pytest.mark.integration
@pytest.mark.slow
def test_nikto_scan_example_com(tmp_path: Path) -> None:
    """`nikto -host https://example.com -maxtime 90s` self-terminates
    gracefully, writes its ``-output`` file, and our parser produces a
    structured items list. Slow: budget ~2 minutes.

    Pass ``max_time`` so nikto stops on its own terms; without it the
    subprocess timeout SIGKILLs nikto mid-scan and loses the output
    file. Add ``-k "not nikto"`` to deselect.
    """
    if not tool_available("nikto"):
        pytest.skip("nikto not installed")

    ctx = _ctx(
        tmp_path,
        "bb.stage4.nikto",
        {"hosts": [NIKTO_TARGET], "max_time": 90},
    )
    result = nikto_scan.run(ctx)
    assert result.success, result.error

    txt_path = next(p for p in result.artifacts if p.suffix == ".txt")
    json_path = next(p for p in result.artifacts if p.suffix == ".json")
    raw = txt_path.read_text()
    payload = json.loads(json_path.read_text())

    assert payload["host"] == NIKTO_TARGET
    assert isinstance(payload["items"], list)
    assert raw.strip(), "nikto produced no output (did -maxtime / -output land?)"
    # The banner block ("- Nikto v2.x.x") is in every nikto output
    assert "Nikto" in raw, "nikto banner missing from output"
    # Findings list may be empty for a low-surface target like
    # example.com but must always be a list, never None.
    assert isinstance(result.findings, list)


# ──────────────────────────── nvd_lookup (direct) ────────────────────────────


@pytest.mark.network
@pytest.mark.integration
def test_nvd_lookup_query_returns_parseable_cves() -> None:
    """`nvd_lookup._query_nvd` against the live NVD API returns at
    least one CVE record for the well-known keyword 'log4j', and
    `_flatten` turns each record into the schema we post back to the
    engine.

    We exercise the helpers directly rather than the engine-aware
    `run()` entry point — `run()` is covered by the standard Phase 2
    integration tests; the smoke test's job is to confirm the NVD API
    response shape hasn't drifted under us.
    """
    try:
        raw = nvd_lookup._query_nvd(NVD_KEYWORD, timeout=20)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"NVD API unreachable / rate-limited: {e}")

    assert raw, f"NVD returned 0 results for keyword {NVD_KEYWORD!r}"

    flat = [nvd_lookup._flatten(v) for v in raw]
    sample = flat[0]
    # Every flattened row must have the engine-side post-back schema
    expected_keys = {"cve_id", "cvss_score", "severity", "summary", "references"}
    missing_keys = expected_keys - set(sample.keys())
    assert not missing_keys, f"NVD flatten missing keys: {missing_keys}"

    assert sample["cve_id"], "cve_id is empty"
    assert sample["cve_id"].startswith("CVE-"), sample["cve_id"]
    assert isinstance(sample["references"], list)
    # Most modern CVEs have a CVSS v3.x score; allow None just in case
    # NVD returns a record with only v2 metrics or none at all.
    if sample["cvss_score"] is not None:
        assert 0.0 <= float(sample["cvss_score"]) <= 10.0
        assert sample["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"} or \
            sample["severity"] is None
