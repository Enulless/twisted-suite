"""Phase 3 — WordPress stress modules unit tests."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from twisted.modules.base import ModuleContext
from twisted.modules.wpstress import (
    ab_baseline,
    endpoint_stress,
    exposed_files,
    headers_diff,
    remediation,
    wpscan_run,
    wrk_escalating,
)


def _ctx(work_dir: Path, **params) -> ModuleContext:
    return ModuleContext(
        engagement_id=1, step_id="wp.test", procedure="wp_stress",
        stage="phase1", params=params, work_dir=work_dir, scope=None,
        timestamp=datetime(2026, 4, 25, 1, 0, 0), worker_id="t", worker_host="wsl",
    )


# ──────────────────────────── ab_baseline ────────────────────────────


SAMPLE_AB = """
This is ApacheBench, Version 2.3
Server Software:        nginx/1.20.1
Server Hostname:        acme.example
Server Port:            443

Document Path:          /
Document Length:        12345 bytes

Concurrency Level:      5
Time taken for tests:   1.234 seconds
Complete requests:      100
Failed requests:        0
Non-2xx responses:      0
Total transferred:      1234567 bytes
HTML transferred:       1234500 bytes
Requests per second:    81.04 [#/sec] (mean)
Time per request:       61.69 [ms] (mean)
Transfer rate:          977.34 [Kbytes/sec] received

Percentage of the requests served within a certain time (ms)
  50%     50
  66%     60
  75%     70
  80%     80
  90%     90
  95%    100
  98%    110
  99%    120
 100%    130 (longest request)
"""


class TestAbBaseline:
    def test_parse_metrics(self) -> None:
        m = ab_baseline.parse_ab(SAMPLE_AB)
        assert m["requests_per_sec"] == 81.04
        assert m["mean_ms"] == 61.69
        assert m["p99_ms"] == 120
        assert m["error_rate"] == 0.0

    def test_run_when_ab_missing(self, tmp_path: Path) -> None:
        with patch.object(ab_baseline, "tool_available", return_value=False):
            r = ab_baseline.run(_ctx(tmp_path, url="acme.example"))
        assert not r.success
        assert "ab" in (r.error or "").lower()

    def test_run_with_stubbed_ab(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        cr = CommandResult(cmd=[], returncode=0, stdout=SAMPLE_AB, stderr="", duration_ms=1)
        with patch.object(ab_baseline, "tool_available", return_value=True), \
             patch.object(ab_baseline, "run_cmd", return_value=cr):
            r = ab_baseline.run(_ctx(tmp_path, url="acme.example", requests=100, concurrency=5))
        assert r.success
        assert "rps=81.04" in r.summary


# ──────────────────────────── wrk_escalating ────────────────────────────


SAMPLE_WRK = """
Running 30s test @ https://acme.example
  4 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    50.10ms   12.30ms  300ms   80.00%
    Req/Sec     1.50k    150       2.50k    65.00%
  Latency Distribution
    50%   45ms
    75%   55ms
    90%   80ms
    99%  150ms
  60000 requests in 30.00s, 100MB read
Requests/sec:   2000.00
Transfer/sec:      3.33MB
"""


class TestWrkEscalating:
    def test_parse(self) -> None:
        m = wrk_escalating.parse_wrk(SAMPLE_WRK)
        assert m["requests_per_sec"] == 2000.00
        assert m["requests_total"] == 60000
        assert m["p99_latency"] == "150ms"

    def test_run_when_missing(self, tmp_path: Path) -> None:
        with patch.object(wrk_escalating, "tool_available", return_value=False):
            r = wrk_escalating.run(_ctx(tmp_path, url="acme.example"))
        assert not r.success

    def test_saturation_detected_on_high_error(self, tmp_path: Path) -> None:
        bad = SAMPLE_WRK + "\nNon-2xx or 3xx responses: 50000\nSocket errors: connect 0, read 0, write 0, timeout 5"
        from twisted.core.runner import CommandResult
        cr = CommandResult(cmd=[], returncode=0, stdout=bad, stderr="", duration_ms=1)
        with patch.object(wrk_escalating, "tool_available", return_value=True), \
             patch.object(wrk_escalating, "run_cmd", return_value=cr):
            r = wrk_escalating.run(_ctx(tmp_path, url="acme.example",
                                         duration=1, threads=1, rounds=[10, 50, 100]))
        assert r.success
        # Should bail at first round with high errors
        assert r.extra["saturation_concurrency"] == 10


# ──────────────────────────── endpoint_stress ────────────────────────────


class TestEndpointStress:
    def test_run_when_missing(self, tmp_path: Path) -> None:
        with patch.object(endpoint_stress, "tool_available", return_value=False):
            r = endpoint_stress.run(_ctx(tmp_path, url="acme.example"))
        assert not r.success

    def test_iterates_endpoints(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        cr = CommandResult(cmd=[], returncode=0, stdout=SAMPLE_AB, stderr="", duration_ms=1)
        with patch.object(endpoint_stress, "tool_available", return_value=True), \
             patch.object(endpoint_stress, "run_cmd", return_value=cr):
            r = endpoint_stress.run(_ctx(tmp_path, url="acme.example",
                                         requests=10, concurrency=2))
        assert r.success
        assert len(r.extra["endpoints"]) == 4


# ──────────────────────────── exposed_files ────────────────────────────


class _FakeResponse:
    def __init__(self, status: int, content: bytes = b""):
        self.status_code = status
        self.content = content


class TestExposedFiles:
    def test_probe_marks_hits(self) -> None:
        # Pretend wp-config.php.bak (status 200) and xmlrpc.php (status 200) are exposed
        sess = MagicMock()
        sess.get.side_effect = [
            _FakeResponse(200, b"wp-config content"),  # wp-config.php.bak
            _FakeResponse(404),                         # wp-config.php~
            _FakeResponse(404),                         # wp-config.txt
            _FakeResponse(404),                         # .env
            _FakeResponse(404),                         # debug.log
            _FakeResponse(404),                         # wp-content/debug.log
            _FakeResponse(200, b"<?xml..."),            # xmlrpc.php
            _FakeResponse(404),                         # .git/config
            _FakeResponse(404),                         # .git/HEAD
            _FakeResponse(404),                         # backup.zip
            _FakeResponse(404),                         # backup.tar.gz
            _FakeResponse(404),                         # install.php
            _FakeResponse(404),                         # readme.html
        ]
        results = exposed_files.probe("acme.example", session=sess)
        statuses_200 = [r for r in results if r.get("status") == 200]
        assert len(statuses_200) == 2

    def test_run_emits_finding_drafts(self, tmp_path: Path) -> None:
        sess = MagicMock()
        sess.get.return_value = _FakeResponse(200, b"X")
        with patch("twisted.modules.wpstress.exposed_files.requests.Session", return_value=sess):
            r = exposed_files.run(_ctx(tmp_path, host="acme.example"))
        # Every probed path returns 200, so every entry becomes a finding
        assert r.success
        assert len(r.findings) == len(exposed_files.SENSITIVE_PATHS)


# ──────────────────────────── headers_diff ────────────────────────────


class TestHeadersDiff:
    def test_diff_sets(self) -> None:
        baseline = {"Server": "nginx", "Cache-Control": "no-cache"}
        stressed = {"Server": "nginx", "X-Powered-By": "PHP/7.2.26",
                    "Cache-Control": "private"}
        d = headers_diff.diff(baseline, stressed)
        assert "x-powered-by" in d["added"]
        assert "cache-control" in d["changed"]
        assert d["removed"] == {}

    def test_run_with_stubbed_audit(self, tmp_path: Path) -> None:
        with patch.object(headers_diff, "audit_headers",
                           return_value={"host": "acme.example", "status": 500,
                                         "headers": {"Server": "nginx", "X-Powered-By": "PHP/7.2.26"}}):
            r = headers_diff.run(_ctx(tmp_path, host="acme.example",
                                       baseline_headers={"Server": "nginx"}))
        assert r.success
        # X-Powered-By is a leaky header — should produce a finding (case-insensitive match)
        titles = [f.title.lower() for f in r.findings]
        assert any("x-powered-by" in t for t in titles)


# ──────────────────────────── wpscan_run ────────────────────────────


SAMPLE_WPSCAN = {
    "version": {
        "number": "5.8.1",
        "vulnerabilities": [
            {"title": "Core stored XSS", "references": {"cve": ["2021-99999"]},
             "description": "..."},
        ],
    },
    "plugins": {
        "vulnerable-plugin": {
            "version": {"number": "1.2.3"},
            "vulnerabilities": [
                {"title": "SQLi", "references": {"cve": ["2022-12345"]},
                 "description": "SQL injection in ..."},
            ],
        },
    },
    "themes": {},
}


class TestWPScan:
    def test_run_when_missing(self, tmp_path: Path) -> None:
        with patch.object(wpscan_run, "tool_available", return_value=False):
            r = wpscan_run.run(_ctx(tmp_path, host="acme.example"))
        assert not r.success

    def test_parse_findings_from_json(self, tmp_path: Path) -> None:
        import json as _json

        from twisted.core.runner import CommandResult
        cr = CommandResult(cmd=[], returncode=0,
                           stdout=_json.dumps(SAMPLE_WPSCAN), stderr="", duration_ms=1)
        with patch.object(wpscan_run, "tool_available", return_value=True), \
             patch.object(wpscan_run, "run_cmd", return_value=cr):
            r = wpscan_run.run(_ctx(tmp_path, host="acme.example"))
        assert r.success
        titles = [f.title for f in r.findings]
        assert any("WordPress core: Core stored XSS" in t for t in titles)
        assert any("vulnerable-plugin" in t for t in titles)

    def test_non_json_output_is_failure(self, tmp_path: Path) -> None:
        from twisted.core.runner import CommandResult
        cr = CommandResult(cmd=[], returncode=0, stdout="some text", stderr="", duration_ms=1)
        with patch.object(wpscan_run, "tool_available", return_value=True), \
             patch.object(wpscan_run, "run_cmd", return_value=cr):
            r = wpscan_run.run(_ctx(tmp_path, host="acme.example"))
        assert not r.success
        assert "json" in (r.error or "").lower()


# ──────────────────────────── remediation ────────────────────────────


class TestRemediation:
    def test_build_matrix_orders_by_severity(self, tmp_path: Path) -> None:
        fake_client = MagicMock()
        fake_client.get.return_value = [
            {"id": 1, "title": "Missing CSP",        "severity": "low",     "status": "draft"},
            {"id": 2, "title": "wp-config.php.bak",   "severity": "critical","status": "draft"},
            {"id": 3, "title": "Outdated plugin XYZ", "severity": "high",   "status": "draft"},
        ]
        with patch.object(remediation, "get_client", return_value=fake_client):
            r = remediation.build_matrix(_ctx(tmp_path, engagement_id=1))
        assert r.success
        # Read JSON artifact and check ordering by fix_by_days
        import json as _json
        data = _json.loads(next(p for p in r.artifacts if p.suffix == ".json").read_text())
        order = [row["title"] for row in data]
        assert order[0] == "wp-config.php.bak"  # critical
        assert order[-1] == "Missing CSP"        # low
        # Remediation hints are picked up
        assert ".htaccess" in data[0]["remediation"]
