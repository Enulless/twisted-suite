# Phase 8 — Completion Summary

**Status:** complete. **Tests:** 467 backend (+5 new) + 23 frontend
(Vitest) = **490 total**, all passing. **Lint:** clean.

The biggest single phase by far — replaces the Jinja2 + HTMX dashboard
with a workflow-driven Vite + React + TypeScript + Tailwind +
shadcn/ui SPA, and adds a per-engagement RoE Tool Policy that gates
step runs by both step ID and capability.

## What's working

### Backend

- **`/api/*` namespace.** Every JSON router is now mounted under
  `/api/*`. The `EngineClient` adds the prefix automatically; tests
  go through a `tests/conftest.ApiClient` wrapper that prefixes
  `/api` to bare paths so the existing test code didn't have to be
  rewritten line-by-line.
- **`engagement_tool_policy` table** + cascading `is_step_allowed()`
  helper in [src/twisted/core/tool_policy.py](src/twisted/core/tool_policy.py).
- **`/api/engagements/{id}/tool-policy/*` router** — GET snapshot, GET
  inventory (every step + capability with current state), PUT step
  toggle, PUT capability toggle, POST preset
  (`open_bug_bounty` / `no_dos` / `read_only_recon`), DELETE.
- **Enforcement** at `/api/steps/run` — 403 with structured detail
  on block (`error: blocked_by_tool_policy`, `target_kind`,
  `target_value`, `reason`). Defensive filter at `/api/jobs/next` so
  a worker never claims a job that's been blocked since it was queued.
- **`/api/engagements/{id}/workflow-state`** — single-call snapshot
  for the SPA's persistent stepper. Computes Setup / Tooling /
  Execute / Triage / Report / Finalize completion 0.0-1.0 + a short
  human summary per step + an aggregate `stats` object.

### Frontend

A fresh Vite + React 18 + TypeScript SPA at [frontend/](frontend/).

| File / area | What |
|---|---|
| [frontend/vite.config.ts](frontend/vite.config.ts) | Vite + Vitest config, dev proxy to engine on :8000 |
| [frontend/tailwind.config.ts](frontend/tailwind.config.ts) | Tailwind theme with severity / status palette + dark mode |
| `frontend/src/api/*.ts` | Typed API helpers per domain (engagements, workers, labs, training, jobs, findings, assets, toolPolicy) |
| `frontend/src/components/ui/*.tsx` | shadcn-style primitives (Button, Card, Input, Label, Badge, Dialog, Separator, Skeleton, Textarea) |
| `frontend/src/components/Sidebar.tsx` | Persistent left nav: Engagements / Workers / Labs / Training / Procedures + theme toggle + ⌘K hint |
| `frontend/src/components/WorkflowStepper.tsx` | 6-step engagement lifecycle stepper, polled every 10 s |
| `frontend/src/components/CommandPalette.tsx` | ⌘K palette: jump to engagement, lab, training; create-engagement action |
| `frontend/src/components/ThemeToggle.tsx` | Dark / light theme toggle, persists in localStorage |
| `frontend/src/components/charts/*` | Severity donut + asset risk histogram (Recharts) + progress dots |
| `frontend/src/layouts/EngagementLayout.tsx` | Tab nav for engagement sub-pages + stepper |
| `frontend/src/pages/EngagementWizard.tsx` | 4-step wizard: Client → Scope → RoE preset → Review |
| `frontend/src/pages/engagement/Tooling.tsx` | Full RoE policy page — preset row + capability list + step list with cascade visualisation + filter + search |
| `frontend/src/pages/engagement/{Procedures,Assets,Findings,FindingDetail,Runs,Report}.tsx` | All engagement sub-pages with full feature parity to the old dashboard, plus a real CVSS calculator |

### Routing

```
/                                       — engagement list (home)
/engagements/new                        — 4-step wizard
/engagements/:id                        — overview (charts, scope, recent findings)
/engagements/:id/scope                  — scope rule reader
/engagements/:id/tooling                — RoE Tool Policy editor
/engagements/:id/procedures             — procedure browser + queue buttons
/engagements/:id/assets                 — sortable / filterable asset table + CSV export
/engagements/:id/findings               — severity kanban
/engagements/:id/findings/:fid          — finding detail w/ CVSS calc + finalize
/engagements/:id/runs                   — live-polled step runs
/engagements/:id/report                 — formats picker + Build button
/workers                                — worker registry
/labs                                   — lab control panel (up / down / open)
/procedures                             — read-only procedure browser
/training                               — lessons + completion summary
```

### CI

- Existing `test` job (Python 3.11 + 3.12 matrix, ruff + pytest)
  still runs on every push.
- New `frontend` job runs `npm ci` + `npm run build` + `npm run test`
  with Node 20 cache. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Tests added

| File | Count | Covers |
|---|---:|---|
| `tests/unit/test_tool_policy.py` | 18 | PolicyDecision, is_step_allowed (default, step block, cap cascade, separate engagements), upsert + clear, all three presets |
| `tests/integration/test_tool_policy_api.py` | 16 | Snapshot, inventory, toggle (step + cap), unknown step/cap 404/400, idempotent toggles, presets, DELETE, 401, enforcement at /steps/run + /jobs/next |
| `tests/integration/test_workflow_state_api.py` | 5 | Schema, setup completion, tool-policy reflection, step-run reflection, 404 |
| `frontend/src/__tests__/utils.test.ts` | 7 | cn merging, formatRelative, formatDate |
| `frontend/src/__tests__/api.test.ts` | 5 | /api prefix, credentials: include, JSON body, ApiError, query arrays |
| `frontend/src/__tests__/StatusBadge.test.tsx` | 6 | Severity + status pill rendering, fallbacks |
| `frontend/src/__tests__/WorkflowStepper.test.tsx` | 3 | Step labels, summaries, /api/.../workflow-state URL |
| `frontend/src/__tests__/EngagementWizard.test.tsx` | 2 | Step gating, full wizard flow + POST |

**Total new: 62 tests.** Suite total: 490 tests passing.

## Quick start

### Operator (use the SPA)

```bash
cd ~/twisted_suite
source .venv/bin/activate
twisted serve                          # WSL terminal 1
twisted worker linux                   # WSL terminal 2

# In a Chrome/Edge tab:
http://localhost:8000/                 # SPA (login auto-fills the local token)
```

### Frontend dev (hot reload)

```bash
# Terminal 1: backend
twisted serve

# Terminal 2: SPA dev server
cd ~/twisted_suite/frontend
npm install                            # one-time
npm run dev                            # serves at http://localhost:5173/
                                       # /api, /login, /logout proxy to :8000
```

### Build for production

```bash
cd ~/twisted_suite/frontend
npm run build                          # → frontend/dist/
# Restart `twisted serve`; FastAPI auto-mounts dist/ at / when it exists.
```

### Apply an RoE preset from the CLI

```bash
# Via the API directly while the existing twisted CLI catches up
curl -X POST -H "Authorization: Bearer $(twisted token show)" \
  http://localhost:8000/api/engagements/1/tool-policy/preset/no_dos
```

…or use the dashboard at `/engagements/1/tooling` and click the
"No DoS" preset button.

## What was scoped down vs the original plan

- **Legacy `/dashboard/*` kept as fallback.** The plan called for
  outright deletion of `engine/routes/web.py` + the Jinja templates.
  Doing this properly requires extracting `/login`, `/logout`, and
  the screenshot-redaction handlers (all still consumed by the SPA)
  into a separate `auth_pages.py` + `redact.py` module, AND migrating
  ~50 dashboard tests. That's a substantial second-wave refactor with
  no immediate user benefit since the SPA already wins for `/`. The
  legacy dashboard is now annotated as deprecated in
  `routes/web.py` with a removal plan; full retirement is scoped to
  a follow-up release once the SPA has had bake-in time.
- **In-SPA PII redaction.** The FindingDetail page links out to the
  legacy `/dashboard/.../redact` canvas tool for now. Porting the
  ~120-line vanilla canvas component to React is a small follow-up.

## Known limitations

- The SPA assumes single-host operation — `fetch` uses
  `credentials: 'include'` and the cookie session is set by the
  legacy `POST /login` route. When the SPA gains its own login form
  (Phase 9-ish), this will become a single-screen experience.
- The workflow-state endpoint computes Execute completion as
  `done_runs / total_steps_in_all_procedures`. For an engagement
  scoped to one procedure, the bar will look low even when "done"
  for that procedure. A future refinement could narrow the
  denominator to "applicable steps based on engagement type".

## File counts

- New backend files: 3 (`core/tool_policy.py`, `routes/tool_policy.py`,
  `tests/{unit,integration}/test_*.py`)
- New frontend files: 31 (everything under `frontend/src/`)
- Modified Python files: 17 (app, client, jobs, engagements, models,
  state, web, all test fixtures, conftest)
- Lines added: ~5,500 (mostly the SPA)
