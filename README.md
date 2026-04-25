# Twisted Pen Testing Suite

Cross-host pen testing automation + training suite. Engine + SQLite live in WSL Ubuntu; Linux and Windows workers both call the engine over HTTP and contribute to one logical engagement.

Covers three procedures end-to-end:

1. **Bug bounty recon & vulnerability assessment** (5 stages)
2. **WordPress stress testing** (4 phases)
3. **WiFi pentest** (4 phases — hardware-dependent, see notes)

## Quick start (WSL)

```bash
cd ~/twisted_suite
virtualenv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# start the engine (binds to 127.0.0.1:8000)
twisted serve

# in a second terminal, start the WSL worker
twisted worker linux
```

## Quick start (Windows)

From PowerShell, after WSL is running with the repo at `\\wsl$\Ubuntu\home\<you>\twisted_suite`:

```powershell
python -m venv $env:USERPROFILE\.twisted\venv
& $env:USERPROFILE\.twisted\venv\Scripts\Activate.ps1
pip install -e \\wsl$\Ubuntu\home\<you>\twisted_suite

twisted worker windows
```

## Running tests

```bash
pytest                          # unit tests only
pytest -m integration           # integration / e2e
pytest -m "network"             # tests that hit the real internet (manual only)
```

## Status

Phase 1 (foundations + cross-host plumbing) is the current build target. See the plan for full scope.
