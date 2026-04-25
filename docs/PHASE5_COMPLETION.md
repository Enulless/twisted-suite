# Phase 5 — Completion Summary

**Status:** complete. **Tests:** 296/296 passing (+21 new dashboard
tests). **Lint:** clean.

## What's working

The browser dashboard is wired in on top of the FastAPI engine using
Jinja2 + HTMX + a single hand-rolled CSS file. No build step. The
JSON API surface is unchanged and remains the authoritative interface
for the CLI, workers, and integration tests.

### URLs

| Path | What |
|---|---|
| `/` | 307-redirects to `/dashboard/` |
| `/login` | Login form (auto-fills the local token in single-user mode) |
| `/logout` | Clears the session cookie |
| `/static/twisted.css` | Single dark stylesheet, 250 lines |
| `/dashboard/` | Engagements list + worker overview |
| `/dashboard/workers` | Worker status, polled every 5 s via HTMX |
| `/dashboard/procedures` | All loaded procedures + stages + steps |
| `/dashboard/engagements/{id}` | Engagement detail w/ scope + stage progress |
| `/dashboard/engagements/{id}/assets` | Master spreadsheet w/ risk tier |
| `/dashboard/engagements/{id}/findings` | Severity-bucketed kanban |
| `/dashboard/engagements/{id}/findings/{fid}` | Finding detail w/ CVSS calc |
| `/dashboard/engagements/{id}/runs` | Step-run history |
| `/dashboard/engagements/{id}/findings/{fid}/cvss` | HTMX target — computes + persists CVSS |
| `/htmx/workers` | HTMX polling fragment for worker page |

### Auth model

- The JSON API still requires `Authorization: Bearer <token>`.
- Dashboard pages additionally accept a `twisted_token` cookie set by
  `POST /login`. Cookie is HttpOnly, SameSite=Strict, 7-day max-age.
- The `require_dashboard_session` dependency tries the bearer header
  first, then the cookie; on failure raises a 303 to
  `/login?next=<original path>` (which a browser actually follows,
  unlike the JSON 401 the API would return).
- `/login` GET pre-fills the token field by reading
  `~/.twisted/worker.token` directly. This is safe because the file is
  chmod 600 — anyone who can read it can already authenticate
  manually. Saves a copy-paste step in the common single-user case.
- `next` parameter is sanitised to local paths only (no
  `https://evil.example/...` open-redirect).

### CVSS calculator

The finding-detail page renders a base-metric form that posts via HTMX
to `/dashboard/.../cvss`. The handler:

1. Parses the form into a `CVSS:3.1/AV:.../AC:.../...` vector
2. Calls `core.cvss.parse_vector` + `.base_score()` (already verified
   against the FIRST.org reference vectors in Phase 1)
3. Persists the vector + score back to the finding row
4. Returns an HTMX fragment with the score, severity pill, and a
   "Refresh" link to confirm persistence

### Worker polling

The workers page emits an HTMX `<p hx-get="/htmx/workers" hx-trigger="every 5s" hx-swap="outerHTML">` element that re-fetches the same fragment every 5 seconds. The fragment contains both the new contents and a fresh polling element so the cycle continues — no JavaScript required.

## What's NOT in Phase 5 (intentionally)

- **SSE streaming for live scan output.** The plan called for live tail
  on long-running scans; the JSON job/result loop already supports
  this server-side, but the dashboard SSE consumer + a per-step
  console widget will land alongside the docker-lab control panel
  (Phase 7).
- **PII-redaction tool for screenshots.** Browser-side image cropping +
  bounding-box redaction wants a small JS component (still no build
  step — vanilla canvas API). Pulled into Phase 7 with the rest of
  the reporting polish.
- **Docker lab control panel.** Needs the lab compose files from
  Phase 7 first; will surface a button-grid to up/down each lab.
- **Engagement creation form.** Operators currently create engagements
  via `twisted engagement new --client … --scope …`. The dashboard is
  read-mostly in v1; create/edit forms can land in a follow-up.

## Test coverage

`tests/integration/test_web_dashboard.py` covers (with `TestClient` +
in-process FastAPI, no live network):

- Static CSS served, login form renders w/ pre-filled token
- Login rejects bad tokens (401, form re-rendered)
- Login sets cookie + redirects to `next`
- Open-redirect blocked (`?next=https://evil.example/` rewritten to
  `/dashboard/`)
- Unauthenticated dashboard requests redirect to `/login?next=…`
- Root `/` 307-redirects to `/dashboard/`
- Logout clears the cookie
- Index, workers, procedures, engagement detail, assets (with
  computed risk tier), findings kanban, finding detail with CVSS
  calc, runs page all render with seed data
- HTMX worker fragment returns a self-replacing element
- CVSS calculator computes a known 10.0/Critical vector, persists it,
  and rejects requests missing metrics
- Full cookie-only browse flow (`/dashboard/` → `/login` POST →
  `/dashboard/` → `/dashboard/workers` all on the cookie alone)
- Asset-page risk tier is correctly computed via
  `risk_scoring.tier(14)` → `high`

## Quick start

```bash
twisted serve                 # WSL, binds to 127.0.0.1:8000
# In a browser on the same host:
http://localhost:8000/        # 307 → /dashboard/ → /login (token auto-filled) → click Login
```

## Known limitations

- The dashboard is read-mostly. CRUD operations beyond the CVSS
  calculator still go through the CLI / JSON API.
- The cookie's `Secure` flag is off because the engine binds to
  plain HTTP on localhost. Production deployments behind a
  TLS-terminating proxy can flip this via an env-var override later.
- HTMX is loaded from `unpkg.com` in `_base.html`. Air-gapped
  installs should vendor `htmx.min.js` into `web/static/` and update
  the `<script src=…>` accordingly.
