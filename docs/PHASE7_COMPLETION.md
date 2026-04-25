# Phase 7 — Completion Summary

**Status:** complete. **Tests:** 428/428 passing (+66 new). **Lint:** clean.

This is the final phase from the original plan. The suite now covers
every shipped feature of the seven-phase scope, plus the deferred
items from Phases 5 and 6.

## What's working

### Practice labs (`docker/labs/`)

Four isolated Docker labs, each on its own bridge network with the
host port pinned via env var:

| Lab id | Default port | Image | Practice for |
|---|---|---|---|
| `dvwa` | `18081` | `vulnerables/web-dvwa` | `bb.stage3.http_probe`, `bb.stage3.headers_audit`, `bb.stage4.nikto`, `bb.stage4.sqlmap_walkthrough`, `bb.stage4.zap_walkthrough` |
| `juice_shop` | `18082` | `bkimminich/juice-shop` | `bb.stage3.http_probe`, `bb.stage3.headers_audit`, `bb.stage3.tls_audit`, `bb.stage4.zap_walkthrough` |
| `wordpress` | `18080` | `wordpress` + `mariadb:11` | All six `wp_stress.phase{1,2,3}.*` automation steps |
| `metasploitable` | `18083` (HTTP) + four others | `tleemcjr/metasploitable2` | The three `wifi.phase4.*_walkthrough` post-ex steps |

Total: **18 step→lab mappings**.

### Lab manager (`src/twisted/labs/`)

- `LabSpec` catalogue with name/desc/compose path/port env/practice steps
- `lab_status / lab_up / take_lab_down / lab_logs` operations that
  shell out to `docker compose` (or legacy `docker-compose`) and
  return typed `LabResult` / `LabStatus` objects
- `docker_available()` capability probe
- `lab_for_step(step_id)` reverse lookup for the practice button
- Every operation is a graceful no-op when docker isn't installed —
  returns `LabResult(success=False, available=False, error=...)`
  instead of raising

### Engine API (`/labs`)

| Method | Path | Notes |
|---|---|---|
| GET | `/labs` | Catalogue + per-lab status |
| GET | `/labs/_meta` | Returns `{docker_available: bool}` |
| GET | `/labs/{id}` | One lab's status |
| POST | `/labs/{id}/up` | Optional `{port, wait_seconds}` body |
| POST | `/labs/{id}/down` | `?keep_volumes=true` to skip `-v` |
| GET | `/labs/{id}/logs?tail=100` | Last N lines |

### Finalize / OneDrive flow (`/engagements/.../finalize`)

| Method | Path | Notes |
|---|---|---|
| GET | `/engagements/{id}/archive-status` | "Is `TWISTED_ARCHIVE_ROOT` set?" |
| POST | `/engagements/{id}/findings/{fid}/finalize` | Copies redacted evidence to `<archive>/engagements/<client>/evidence/finalized/<finding_id>/`, stamps `finalized_at` on the finding + every Evidence row, flips status to `REPORTED` |
| POST | `/engagements/{id}/finalize-report` | Body `{paths: [...]}` — copies each report file into `<archive>/.../reports/` |

The redacted_path always wins over the original path during finalize,
so a finding with both a screenshot and a redacted screenshot ships
only the redacted version to the cold archive.

### Reporting polish

- **Executive one-pager** — `core.reporting.render_executive_html()`
  produces a single-page A4-sized HTML doc with a risk-at-a-glance
  table, top 5 findings, severity-aware recommended next steps, and
  a scope block. Rendered through WeasyPrint (`format=executive_pdf`)
  for a print-ready PDF.
- **Report builder** now accepts `markdown / html / pdf / executive /
  executive_pdf` formats, so `twisted step run bb.stage5.build_report
  -p formats=html,pdf,executive_pdf` produces all four artifacts in one
  go.
- **XLSX exporter** rewritten with six sheets:
  - `Summary` — engagement metadata + severity counts (color-fill)
  - `Findings` — full list with severity row-fill
  - `Assets` — master spreadsheet (in_scope, risk_total, ports, techs)
  - `CVEs` — every asset+CVE row
  - `Risk_Scores` — per-asset risk breakdown with running total
  - `Remediation` — sorted by severity, blank Owner / Due date columns

### CLI additions

```
twisted lab list / status / up / down / logs       # 5 subcommands
twisted finalize status / finding / report          # 3 subcommands
```

### Dashboard additions

| Path | What |
|---|---|
| `/dashboard/labs` | Lab control panel — Up/Down buttons (HTMX), per-lab status, target URL, container list, "Open target ↗" link, expandable practice-step list |
| `/dashboard/labs/{id}/up` | HTMX fragment endpoint — brings lab up via `compose up -d` |
| `/dashboard/labs/{id}/down` | HTMX fragment endpoint — brings lab down with `-v` |
| `/dashboard/labs/{id}/logs?tail=N` | Full-page log view |
| `/dashboard/training/{step}/practice` | "Practice on the lab" button on every training page that maps to a lab. Brings the lab up if it's down, then queues `step` against the lab's target URL as a step run on the latest engagement |
| `/dashboard/engagements/{id}/findings/{fid}/finalize` | "Mark Final" button on finding detail (HTMX fragment). Persists the same status/timestamp updates as the JSON API |
| `/dashboard/engagements/{id}/findings/{fid}/redact` | Browser PII redactor — pure vanilla canvas/JS (~120 lines, served at `/static/redact.js`). Drag rectangles, undo, clear, submit. Server applies via Pillow, saves redacted PNG, attaches as a new evidence row whose `redacted_path` takes precedence in finalize |

Nav link "Labs" added to the base template.

### Tests added

| File | Tests | Covers |
|---|---:|---|
| `tests/unit/test_labs_manager.py` | 14 | catalogue completeness, target-URL env override, step-lookup, `ps` parsing (JSON + legacy), graceful no-ops without docker, compose-command construction with mocked subprocess |
| `tests/unit/test_redact.py` | 10 | Rectangle dataclass, blackout pixel correctness, multi-rectangle independence, file-mode w/ SHA-256, parent-dir creation, invalid image error |
| `tests/unit/test_finalize.py` | 9 | archive-paths resolution (set vs unset), report finalize (skips missing files gracefully), evidence finalize (prefers redacted over original, stamps under per-finding folder) |
| `tests/unit/test_reporting_executive.py` | 8 | executive HTML rendering (header, severity table, top-5 cap, no-findings message, severity-aware recommendations) + regression on existing markdown/html renderers |
| `tests/integration/test_labs_api.py` | 8 | `/labs` catalogue, practice-step mapping, 404, `/_meta` capability probe, up/down/logs with mocked manager, auth rejection |
| `tests/integration/test_finalize_api.py` | 5 | archive-status (set + unset), finalize-finding archives **redacted** bytes (not original), report finalize, 404 on unknown finding |
| `tests/integration/test_phase7_dashboard.py` | 12 | labs control panel rendering, docker-unavailable warning, up/down/logs HTMX fragments, finalize button persists, practice button surfaces and queues a real step run, redact form GET + POST creates an evidence row, invalid-rectangle JSON 400, nav link |

Total: **66 new tests** (428 passing overall, +66 over Phase 6).

## What's NOT in this phase (intentionally)

Two items from the original plan were scoped out as "nice to have"
and ship in a follow-up:

- **SSE live scan output streaming** — the engine knows job state
  changes; a `/steps/runs/{id}/stream` endpoint that yields SSE
  events is small but the worker-side incremental-output path needs
  meaningful changes to the dispatch loop. Defer until someone
  needs it for genuinely long-running scans.
- **End-to-end smoke tests against the labs in CI** — every
  smoke-test fixture would need a real docker daemon, which is
  flaky in GitHub-hosted runners. The existing Phase 3 lab smoke
  test pattern (with its module-scoped docker-compose fixture) is
  the template — add procedure-by-procedure when you have a
  dedicated runner with docker pre-warmed.

## Quick start

```bash
# Bring up a lab (CLI)
twisted lab up dvwa
twisted lab list
twisted lab logs dvwa --tail 50

# Or from the dashboard
http://localhost:8000/dashboard/labs

# Practice a step against its lab
http://localhost:8000/dashboard/training/bb.stage3.headers_audit
# Click "Run this step against the lab" — the lab spins up if needed,
# the step queues against http://127.0.0.1:18081/, results land in
# /dashboard/engagements/<id>/runs

# Build a full report bundle
twisted step run bb.stage5.build_report \
  -e <client> \
  -p formats=html,pdf,executive_pdf
twisted step run bb.stage5.export_findings -e <client>

# Promote evidence to OneDrive (TWISTED_ARCHIVE_ROOT must be set)
twisted finalize status -e <client>
twisted finalize finding 42 -e <client>
twisted finalize report -e <client> path/to/report.pdf

# Redact a screenshot before finalizing
http://localhost:8000/dashboard/engagements/<id>/findings/<fid>/redact
```

## Final test totals

```
pytest                          → 428 passed,   10 deselected,   ~19 s   (default)
pytest -m network               →   8 passed,    2 skipped,      ~92 s   (live smoke)
pytest -m "network and docker"  → ready to run when docker installed
```

The original 7-phase scope is now complete.
