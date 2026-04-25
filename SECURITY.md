# Security Policy

## Scope

The Twisted Pen Testing Suite is a defensive-research and authorized-engagement
tool. It automates and walks through three procedures (bug-bounty recon,
WordPress stress testing, WiFi pentest) for use against:

- Assets you own
- Assets covered by a written Rules of Engagement
- Assets explicitly listed in a public bug-bounty program's in-scope list

Running any module against assets outside those categories may violate the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or
equivalent legislation in your jurisdiction.

## Built-in safeguards

- **RoE scope filter.** Every module checks `core.scope.Scope.filter()`
  before invoking external tools. Out-of-scope hosts are dropped before the
  subprocess fires.
- **WSL hard-block on WiFi modules.** `wifi.preflight` refuses to run inside
  WSL2 (no USB passthrough by default), preventing accidental evil-twin or
  monitor-mode attempts on a misconfigured host.
- **Polite defaults.** `nmap` uses `-T3` (normal), `nikto` exposes a
  `max_time` cap, and the `wrk` escalating runner stops on the first
  saturation signal.
- **Authentication.** The engine API requires a bearer token from
  `~/.twisted/worker.token`. Bind address defaults to `127.0.0.1` only;
  WSL2 auto-forwards `localhost:8000` to the Windows side, but the engine
  is not reachable from the wider LAN.

## Reporting a vulnerability

If you find a security issue **in this codebase** (not in a target you're
scanning), please **do not** open a public GitHub issue. Instead:

1. Open a private security advisory at
   <https://github.com/Enulless/twisted-suite/security/advisories/new>, or
2. Email the maintainer directly with a description of the issue and steps
   to reproduce.

I will respond within 7 days and aim to publish a fix or mitigation within
30 days of acknowledgement, depending on severity.

## What counts as a vulnerability

Examples of in-scope issues for this repo:

- A way to bypass the RoE scope filter and have the engine dispatch a job
  against an out-of-scope host.
- An unauthenticated endpoint on the engine API.
- A path-traversal bug in evidence/artifact ingestion.
- A code-injection bug in a YAML-driven module parameter.
- A credential-exposure bug (worker token logged in plaintext to a place it
  shouldn't be, etc.).

Examples of **out of scope** for this repo (these are issues with the
*targets* of a scan, not the suite itself):

- A finding produced by a module against a real target. That belongs in your
  engagement report, not a Twisted-suite security advisory.
- Any external tool (`nmap`, `nikto`, `wpscan`, `hashcat`, etc.) — report
  upstream.

## Disclosure timeline

- Day 0: report received, acknowledged within 7 days.
- Day 0–30: investigation, fix development, release planning.
- Day 30: coordinated disclosure (advisory + patched release published
  together). May be extended for severe issues that require ecosystem
  coordination.

Thank you for helping keep this safe.
