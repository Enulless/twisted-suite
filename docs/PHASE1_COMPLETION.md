# Phase 1 — Completion Summary

**Status:** complete. **Tests:** 207/207 passing. **Lint:** clean.

## What's working

The full cross-host plumbing is in place and exercised end-to-end by the
acceptance test (`tests/integration/test_e2e_phase1.py`):

- Engine boots from a fresh data root via `twisted serve` (uvicorn on
  127.0.0.1:8000) and is auto-startable via the WSL systemd user service
  (`scripts/install-engine-systemd.sh`).
- SQLite owned exclusively by the engine; WAL mode, foreign keys on,
  busy-timeout 5 s.
- Bearer token auth with auto-generated token at
  `~/.twisted/worker.token`. Workers, CLI, and (eventually) Windows worker
  read the same file.
- Worker daemon (`twisted worker linux` / `twisted worker windows`) registers,
  long-polls for jobs that match its declared capability tags, dispatches to
  the YAML-referenced `pkg.module:callable`, posts back artifacts, assets,
  findings, and evidence.
- Procedure YAML schema lives in `src/twisted/procedures/bug_bounty.yaml`,
  with the per-step `runtime: linux | windows | either` and `requires: [...]`
  fields the engine uses for routing.
- Six recon modules ported from `recon_ovh.py`: crt.sh, DNS enum, whois,
  HTTP probe, security-headers audit, TLS audit. Each follows the
  `ModuleResult` contract and writes `.txt` + `.json` per the existing
  artifact convention.
- CLI: `twisted version | serve | worker | engagement | procedure | step |
  asset | finding | token | import-ovh`.
- OVH import (`twisted import-ovh`) discovers every step* artifact in the
  existing `Twisted/` OneDrive folder, registers them in place, and
  pre-populates the master spreadsheet from extractable subdomains.
- Reporting primitives render markdown + HTML reports with the bug-bounty
  Part E1/E2 structure; CVSS v3.1 calculator implements the FIRST.org
  formula and is verified against the published reference vectors.

## What's NOT in Phase 1 (intentionally)

These land in their respective phases per the plan:

- The bug-bounty procedure beyond two seed steps (`bb.stage1.crtsh`,
  `bb.stage1.dns_enum`, `bb.stage4.zap_walkthrough`). Phases 2-4 fill out
  every stage of every procedure.
- WordPress stress modules (Phase 3).
- WiFi modules (Phase 4).
- Web dashboard (Phase 5).
- Training mode (Phase 6).
- Docker labs + PDF/XLSX export polish (Phase 7).

## Quick start

```bash
# WSL side (one-time)
cd ~/twisted_suite
virtualenv .venv && source .venv/bin/activate
pip install -e '.[dev]'
twisted serve                    # in one terminal
twisted worker linux             # in another
twisted import-ovh               # third terminal: import existing OVH work
twisted engagement list

# Windows side (PowerShell)
.\scripts\install-windows-worker.ps1 -Distro Ubuntu -WslUser <you>
```

## Known limitations

See `docs/PHASE1_ERROR_LOG.md` for the full audit trail. Highlights:

- Linux pen-test tools (`dig`, `nmap`, `openssl`, etc.) must be installed
  for the auto-modules to actually run. Tests use mocks; production runs
  shell out for real.
- WSL2 USB passthrough is required for WiFi work — covered in Phase 4.
- The web dashboard isn't built yet, so the operator interacts via CLI
  for now. The engine API is fully usable; the dashboard in Phase 5 just
  adds a browser surface on top.
