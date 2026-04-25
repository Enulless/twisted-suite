# Twisted Pen Testing Suite

[![CI](https://github.com/Enulless/twisted-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/Enulless/twisted-suite/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Proprietary-lightgrey)](#license)

Cross-host pen-testing automation + training suite. A FastAPI engine and SQLite live in WSL Ubuntu; Linux and Windows workers both call the engine over HTTP and contribute artifacts to one logical engagement. Drives all three of the canonical procedures end-to-end:

1. **Bug-bounty recon & vulnerability assessment** — 5 stages (recon → asset surfacing → tech & CVE mapping → vulnerability validation → reporting)
2. **WordPress stress testing** — 4 phases (baseline → escalating concurrency → endpoint isolation → remediation diff)
3. **WiFi pentest** — 4 phases (pre-flight → enumeration → handshake/WPS attacks → post-exploitation)

> **Status:** All eight phases complete. The original 7-phase scope
> shipped (foundations + 3 procedures + dashboard + training + labs +
> reporting), and Phase 8 replaces the Jinja2 dashboard with a
> Vite + React + TypeScript + Tailwind + shadcn/ui SPA driven by an
> engagement-lifecycle stepper, plus a per-engagement RoE Tool Policy
> that gates step runs by both step ID and capability. Documented in
> [`docs/PHASE1_COMPLETION.md`](docs/PHASE1_COMPLETION.md),
> [`docs/PHASE5_COMPLETION.md`](docs/PHASE5_COMPLETION.md),
> [`docs/PHASE6_COMPLETION.md`](docs/PHASE6_COMPLETION.md),
> [`docs/PHASE7_COMPLETION.md`](docs/PHASE7_COMPLETION.md), and
> [`docs/PHASE8_COMPLETION.md`](docs/PHASE8_COMPLETION.md).

## Architecture at a glance

```
                         ┌──────────────────────────┐
       Windows worker ──▶│  FastAPI Engine + SQLite │◀── WSL worker
       (ZAP, Burp, …)    │    (WSL, port 8000)      │    (nmap, dig, sqlmap, …)
                         └────────────┬─────────────┘
                                      │
                            HTTP/JSON │ HTMX dashboard (Phase 5)
                                      ▼
                              http://localhost:8000
```

- **One engine, many workers.** A single FastAPI process owns `twisted.db`. Nothing else writes to it. Avoids DrvFs locking corruption.
- **Capability routing.** Each step's YAML declares `runtime: linux | windows | either` and a list of `requires:` capability tags; the engine routes jobs to a worker that advertises a matching set.
- **Split storage.** Hot/transient artifacts live on the WSL filesystem (`~/twisted/data/`); finalized reports land in OneDrive (`/mnt/c/.../Twisted/data/`).
- **Shared-token auth.** Bearer token at `~/.twisted/worker.token`, generated on first `twisted serve`.

## Quick start (WSL)

```bash
git clone https://github.com/Enulless/twisted-suite ~/twisted_suite
cd ~/twisted_suite
virtualenv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# In one terminal: start the engine
twisted serve

# In another: start the WSL worker (auto-detects installed tools)
twisted worker linux

# Optional: import any existing OVH artifacts as the first engagement
twisted import-ovh
twisted engagement list
```

The engine binds to `127.0.0.1:8000`. WSL2 auto-forwards localhost to the Windows host, so a Chrome/Edge tab pointed at `http://localhost:8000` reaches the React SPA from Windows. The token is auto-filled on the login page when the dashboard runs on the same host as the engine — usually a single click.

### Frontend dev (hot reload)

```bash
cd ~/twisted_suite/frontend
npm install                # one-time
npm run dev                # serves at http://localhost:5173/
                           # /api, /login, /logout proxy to :8000
```

Production build (`npm run build` → `frontend/dist/`) is automatically served by FastAPI at `/` whenever the directory exists. Legacy Jinja dashboard remains at `/dashboard/*` for the time being.

## Quick start (Windows worker)

From PowerShell, after WSL is running with the repo cloned at `\\wsl$\Ubuntu\home\<you>\twisted_suite`:

```powershell
.\scripts\install-windows-worker.ps1 -Distro Ubuntu -WslUser <you>
twisted worker windows
```

Or manually:

```powershell
python -m venv $env:USERPROFILE\.twisted\venv
& $env:USERPROFILE\.twisted\venv\Scripts\Activate.ps1
pip install -e \\wsl$\Ubuntu\home\<you>\twisted_suite

twisted worker windows
```

## CLI surface

| Command | Description |
|---|---|
| `twisted serve` | Start the FastAPI engine + dashboard (WSL only) |
| `twisted worker {linux,windows}` | Start a worker daemon (advertises tools on PATH as capabilities) |
| `twisted workers list` | List registered workers and capabilities |
| `twisted engagement new --client OVH --scope scope.txt` | Create an engagement |
| `twisted procedure list` / `twisted stage run bb.stage1` | Procedure + stage operations |
| `twisted step run bb.stage1.crtsh` | Run a single step |
| `twisted asset list --env staging --risk high` | Query the master spreadsheet |
| `twisted finding new …` | Create a finding |
| `twisted evidence add finding-42 ./shot.png --redact` | Attach evidence (with PII redaction) |
| `twisted report build --format html,pdf,csv` | Build the engagement report |
| `twisted finalize finding-42` | Promote evidence into the OneDrive finalized tree |
| `twisted import-ovh` | One-shot import of historic `recon_ovh_*` artifacts |
| `twisted train list` / `show` / `quiz` / `progress` | Training mode: lessons + interactive quizzes + completion tracking |
| `twisted train extract --bb <docx> --wp <docx> --wifi <docx>` | Rebuild lesson markdown from procedure docx files |
| `twisted lab list` / `status` / `up` / `down` / `logs` | Practice labs (DVWA / Juice Shop / WordPress / Metasploitable2) |
| `twisted finalize status` / `finding` / `report` | Promote evidence + reports to the OneDrive cold archive |
| `twisted token verify` | Health check (engine reachable, token valid) |

Every CLI command is just an HTTP client to the engine — no direct DB access from any process other than the engine.

## Tests

Three test layers, with progressively more permissive networking:

```bash
pytest                                 # default: 275 tests, hermetic, ~9 s
pytest -m network                      # live-target smoke tests (~92 s, needs nmap/dig/openssl/whois/nikto on PATH)
pytest -m "network and not slow"       # skip nikto (~10 s)
pytest -m "network and docker"         # WP-lab tests against docker/labs/wordpress (needs docker + ab + wrk)
pytest -v -k "test_phase1"             # run a specific subset
```

The default `pytest` invocation skips anything marked `network` or `docker`, so it stays fast and works offline. The CI workflow runs the default suite on every push and the live smoke tests on a weekly schedule (`workflow_dispatch` to trigger on demand).

### Tooling required for live tests

| Suite | Tools |
|---|---|
| Phase 2 round 1 (`test_smoke_phase2_live.py`) | `dig`, `nmap`, `openssl` |
| Phase 2 round 2 (`test_smoke_phase2_more_live.py`) | `whois`, `nikto`, plus internet access for the NVD API |
| Phase 3 WordPress lab (`test_smoke_phase3_wp_lab.py`) | `docker`, `docker compose`, `apache2-utils` (for `ab`), `wrk` |

Install on Ubuntu/WSL:

```bash
sudo apt install -y dnsutils nmap whois openssl nikto apache2-utils wrk docker.io
```

## Repo layout

```
twisted_suite/
├── src/twisted/
│   ├── core/         # db, models, scope, runner, evidence, reporting, cvss, settings
│   ├── engine/       # FastAPI app, routes, auth, schemas, state
│   ├── worker/       # daemon, dispatch, tool detection
│   ├── client/       # HTTP client used by CLI + workers
│   ├── cli/          # typer commands
│   ├── modules/
│   │   ├── recon/    # crtsh, dns_enum, whois, http_probe, headers_audit, tls_audit,
│   │   │             # aggregators, email_security, nmap, nikto, nvd_lookup, risk_scoring
│   │   ├── webvuln/  # (Phase 2 walkthrough hooks)
│   │   ├── wpstress/ # ab, wrk, locust, wpscan, exposed-files, headers diff, remediation
│   │   ├── wifi/     # preflight, monitor, airodump, handshake, hashcat, wps, post-exploit
│   │   └── report/   # builder + spreadsheet exporter
│   ├── procedures/   # *.yaml — single source of truth for steps, capabilities, walkthroughs
│   ├── training/     # (Phase 6) lessons + quizzes auto-extracted from the docx procedures
│   └── web/          # (Phase 5) Jinja2 templates for the HTMX dashboard
├── docker/labs/      # WordPress lab (Phase 7 will add DVWA, Juice Shop, etc.)
├── docs/             # phase completion notes, error logs
├── scripts/          # install-engine-systemd.sh, install-windows-worker.ps1
└── tests/
    ├── unit/         # 240+ unit tests (mocked subprocess + HTTP)
    └── integration/  # end-to-end + live-network smoke tests
```

## Procedure YAML — the source of truth

Every step is encoded once and drives both the automated module and the training lesson:

```yaml
- id: bb.stage1.crtsh
  name: "Certificate Transparency Log Harvesting"
  stage: 1
  mode: auto                        # auto | walkthrough | hybrid
  runtime: either                   # linux | windows | either
  requires: []                      # capability tags the worker must advertise
  module: twisted.modules.recon.crtsh:run
  params: { domain: "{{engagement.primary_domain}}" }
  outputs: [{ kind: asset, source: "crt.sh" }]
  training: { lesson: bb/stage1/crtsh.md, quiz: bb/stage1/crtsh.yaml }
```

Walkthrough steps (ZAP, Wireshark, Burp, manual XSS, evil-twin) use `mode: walkthrough` and the worker just orchestrates operator prompts — file uploads land on the worker's local FS, then get path-translated and registered with the engine.

## Security

This is a defensive-research and authorized-engagement tool. Do not run any module against assets you do not own or have explicit, documented authorization to test. See [`SECURITY.md`](SECURITY.md) for the responsible-disclosure policy.

## License

Proprietary. All rights reserved. See [`pyproject.toml`](pyproject.toml).
