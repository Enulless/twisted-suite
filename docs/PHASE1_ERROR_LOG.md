# Phase 1 — Error Log

This file tracks any issue encountered during Phase 1 that could not be
resolved before moving to the next sub-task. Carried over to subsequent
phases for follow-up. Empty entries are intentional — issues encountered
*and resolved* during Phase 1 are listed under "Resolved during build" for
posterity.

## Outstanding (carried into Phase 2)

_None._ All Phase 1 sub-tasks completed with green tests.

## Resolved during build

1. **`Evidence` ORM missing `engagement` relationship** — first version of
   `core/models.py` only had `engagement_id` FK. Added `engagement` ORM
   relationship so existing code paths that pass `engagement=eng` to the
   `Evidence` constructor work cleanly. Caught by `test_finding_with_evidence`.

2. **Pydantic-Settings parsed empty `TWISTED_ARCHIVE_ROOT=""` as `PosixPath('.')`** —
   added a `field_validator(mode="before")` that coerces empty string to
   `None`, so unsetting the env var actually disables the cold archive.
   Caught by `test_archive_disabled_when_unset`.

3. **Asset upsert failed `UNIQUE(engagement_id, host)` on dedup-within-batch** —
   the original handler did one SELECT per item, but with `autoflush=False`
   sessions don't see uncommitted INSERTs from earlier in the same loop.
   Extracted a shared `upsert_assets_in_session` helper that maintains a
   `seen_in_batch` dict, used by both `/engagements/{id}/assets` and
   `/jobs/{id}/result`. Caught by `test_upsert_assets_respects_scope`.

4. **httpx ASGITransport now async-only in 0.28+** — first attempt at CLI
   integration tests patched `httpx.Client.__init__` to inject an
   `ASGITransport`. Newer httpx removed the synchronous `handle_request` code
   path. Switched the CLI tests to spin up a real `uvicorn.Server` in a
   background thread on an ephemeral port, which is also more representative
   of production usage. Caught by `test_engagement_lifecycle`.

5. **`_iter_strings` skipped dict keys** — the OVH import's asset extractor
   recursed into dict *values* but ignored *keys*. The existing OVH artifact
   `02_dns.json` stores domains as keys, so api.ovh.com was missed. Fixed to
   yield keys too, plus added text-file (`.txt` / `.log`) extraction so
   `01_subdomains.txt`-style outputs are also harvested. Caught by
   `test_extracts_subdomains_matching_root` and
   `test_full_import_creates_engagement_and_assets`.

6. **`pip` not in system Python** — the WSL host shipped Python 3.12 without
   `ensurepip`. Bootstrapped pip via `get-pip.py --user`, then installed
   `virtualenv` (which doesn't depend on the broken ensurepip) and used it
   to create `.venv`. Documented in the README quick-start.

7. **`CliRunner(mix_stderr=False)` removed in newer typer/click** — Typer
   0.24 dropped the `mix_stderr` kwarg. Removed it from the test fixture.

8. **Several lint cleanups** — auto-fixed via ruff (`SIM105` for
   `try/except/pass`, `E702` semicolon-separated statements). The CVSS
   formula's `if/else` impact + score blocks were left as-is (ruling out
   `SIM108` ternaries) for readability against the FIRST.org spec.

## Dependencies / environment notes for downstream phases

- **Linux pen-test tools are not installed in this environment.** Tests
  for modules that shell out to `dig`, `whois`, `openssl`, `nmap`, etc.
  use mocks. Phase 2 onwards will exercise real tool invocation when the
  user installs them; the `core.runner.tool_available` checks already
  surface a clean error if a tool is missing.

- **WSL2 systemd may not be enabled by default.** The
  `scripts/install-engine-systemd.sh` script detects this and prints
  setup instructions for `/etc/wsl.conf`.

- **WiFi modules (Phase 4) cannot run in WSL2 by default** — no USB
  passthrough. Already noted in the plan; will hard-block at the worker
  capability layer in Phase 4.
