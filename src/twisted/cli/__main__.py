"""Twisted CLI entry point.

Usage::

    twisted serve                    # start the engine + dashboard (WSL only)
    twisted worker linux             # start a WSL worker
    twisted worker windows           # start a Windows worker (run on Windows side)
    twisted procedure list
    twisted procedure show bb.stage1.crtsh
    twisted engagement new --client OVH --domain ovh.com
    twisted engagement list
    twisted step run bb.stage1.crtsh --engagement OVH
    twisted asset list --engagement OVH
    twisted finding list --engagement OVH
    twisted finding new --engagement OVH --title "..." --severity high
    twisted finalize finding 42
    twisted token show               # print the bearer token
"""

from __future__ import annotations

import json

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..client.api import EngineClient
from ..core.settings import get_settings
from ..engine.auth import ensure_token

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
console = Console()


# ──────────────────────────── lifecycle ────────────────────────────


@app.callback()
def main(
    ctx: typer.Context,
    engine_url: str | None = typer.Option(None, "--engine-url", envvar="TWISTED_ENGINE_URL",
                                          help="Override engine URL (default http://127.0.0.1:8000)"),
    token: str | None = typer.Option(None, "--token", envvar="TWISTED_TOKEN",
                                     help="Override bearer token (default reads token file)"),
) -> None:
    """Twisted Pen Testing Suite — operator CLI."""
    ctx.obj = {"engine_url": engine_url, "token": token}


def _client(ctx: typer.Context) -> EngineClient:
    obj = ctx.obj or {}
    return EngineClient(base_url=obj.get("engine_url"), token=obj.get("token"))


@app.command()
def version() -> None:
    """Print twisted-suite version."""
    rprint(f"twisted-suite {__version__}")


# ──────────────────────────── serve ────────────────────────────


@app.command()
def serve(
    host: str = typer.Option(None, "--host", help="Bind host (default 127.0.0.1)"),
    port: int = typer.Option(None, "--port", help="Bind port (default 8000)"),
    install_systemd: bool = typer.Option(False, "--install-systemd",
                                         help="Install a user systemd unit and exit"),
) -> None:
    """Start the engine + dashboard (WSL only)."""
    settings = get_settings()
    settings.ensure_dirs()
    token = ensure_token(settings)
    rprint(f"[bold green]Engine token[/]: {token}")
    rprint(f"[dim]Token file:[/] {settings.token_file}")

    if install_systemd:
        from .systemd_install import install_user_unit
        unit_path = install_user_unit(settings)
        rprint(f"[bold green]Installed[/] systemd unit: {unit_path}")
        rprint("[dim]Run:[/] systemctl --user daemon-reload "
               "&& systemctl --user enable --now twisted-engine.service")
        return

    import uvicorn

    from ..engine.app import create_app
    bind_host = host or settings.engine_host
    bind_port = port or settings.engine_port
    app_obj = create_app(settings=settings)
    rprint(f"[bold cyan]Twisted engine[/] starting on http://{bind_host}:{bind_port}")
    uvicorn.run(app_obj, host=bind_host, port=bind_port, log_level="info")


# ──────────────────────────── worker ────────────────────────────


worker_app = typer.Typer(help="Worker daemon")
app.add_typer(worker_app, name="worker")


@worker_app.command("linux")
def worker_linux(
    worker_id: str | None = typer.Option(None, "--id"),
    capability: list[str] = typer.Option(None, "--cap",
                                         help="Add an extra capability tag"),
) -> None:
    """Run a WSL/Linux worker."""
    from ..worker.daemon import WorkerDaemon, make_default_config
    cfg = make_default_config("linux", worker_id=worker_id)
    if capability:
        cfg.capabilities = sorted(set([*cfg.capabilities, *capability]))
    rprint(f"[bold cyan]Worker[/] {cfg.worker_id} (linux) starting; caps={cfg.capabilities}")
    WorkerDaemon(cfg).run()


@worker_app.command("windows")
def worker_windows(
    worker_id: str | None = typer.Option(None, "--id"),
    capability: list[str] = typer.Option(None, "--cap"),
) -> None:
    """Run a Windows worker (run from PowerShell on the Windows side)."""
    from ..worker.daemon import WorkerDaemon, make_default_config
    cfg = make_default_config("windows", worker_id=worker_id)
    if capability:
        cfg.capabilities = sorted(set([*cfg.capabilities, *capability]))
    rprint(f"[bold cyan]Worker[/] {cfg.worker_id} (windows) starting; caps={cfg.capabilities}")
    WorkerDaemon(cfg).run()


@worker_app.command("list")
def worker_list(ctx: typer.Context) -> None:
    """Show all workers known to the engine."""
    with _client(ctx) as c:
        rows = c.get("/workers")
    table = Table("id", "os", "status", "capabilities", "last_seen")
    for w in rows:
        table.add_row(w["id"], w["os"], w["status"], ", ".join(w["capabilities"][:6]),
                      str(w["last_seen"]))
    console.print(table)


# ──────────────────────────── engagement ────────────────────────────


eng_app = typer.Typer(help="Engagements")
app.add_typer(eng_app, name="engagement")


@eng_app.command("new")
def eng_new(
    ctx: typer.Context,
    client_name: str = typer.Option(..., "--client"),
    domain: str | None = typer.Option(None, "--domain"),
    scope_file: str | None = typer.Option(None, "--scope-file",
                                          help="Path to a scope file (exact: / wildcard: / oos:)"),
    notes: str | None = typer.Option(None, "--notes"),
) -> None:
    """Create a new engagement."""
    scope: list[dict] = []
    if scope_file:
        from pathlib import Path
        for raw in Path(scope_file).read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, pattern = line.partition(":")
            kind = kind.strip().lower()
            pattern = pattern.strip()
            if kind in ("exact", "wildcard", "oos") and pattern:
                scope.append({"kind": kind, "pattern": pattern})
    payload = {"client": client_name, "primary_domain": domain,
               "notes": notes, "scope": scope}
    with _client(ctx) as c:
        out = c.post("/engagements", json=payload)
    rprint(f"[bold green]Created[/] engagement #{out['id']}: {out['client']}")
    rprint(f"  root: {out['root_dir']}")


@eng_app.command("list")
def eng_list(ctx: typer.Context) -> None:
    with _client(ctx) as c:
        rows = c.get("/engagements")
    t = Table("id", "client", "primary_domain", "status", "created_at")
    for e in rows:
        t.add_row(str(e["id"]), e["client"], e.get("primary_domain") or "-",
                  e["status"], str(e["created_at"]))
    console.print(t)


@eng_app.command("show")
def eng_show(ctx: typer.Context, engagement: str = typer.Argument(...)) -> None:
    eng_id = _resolve_engagement(ctx, engagement)
    with _client(ctx) as c:
        e = c.get(f"/engagements/{eng_id}")
        scope = c.get(f"/engagements/{eng_id}/scope")
    rprint(json.dumps({"engagement": e, "scope": scope}, indent=2, default=str))


def _resolve_engagement(ctx: typer.Context, identifier: str) -> int:
    """Accept either an integer id or a client name."""
    if identifier.isdigit():
        return int(identifier)
    with _client(ctx) as c:
        rows = c.get("/engagements")
    for e in rows:
        if e["client"].lower() == identifier.lower():
            return int(e["id"])
    raise typer.BadParameter(f"no engagement with client name '{identifier}'")


# ──────────────────────────── procedure ────────────────────────────


proc_app = typer.Typer(help="Procedures (bug_bounty / wp_stress / wifi_pentest)")
app.add_typer(proc_app, name="procedure")


@proc_app.command("list")
def proc_list(ctx: typer.Context) -> None:
    with _client(ctx) as c:
        rows = c.get("/procedures")
    t = Table("procedure", "stages", "steps", "name")
    for p in rows:
        n_steps = sum(len(st["steps"]) for st in p["stages"])
        t.add_row(p["id"], str(len(p["stages"])), str(n_steps), p["name"])
    console.print(t)


@proc_app.command("show")
def proc_show(ctx: typer.Context, step_id: str = typer.Argument(...)) -> None:
    proc_id = step_id.split(".", 1)[0]
    with _client(ctx) as c:
        step = c.get(f"/procedures/{proc_id}/steps/{step_id}")
    rprint(json.dumps(step, indent=2, default=str))


# ──────────────────────────── step ────────────────────────────


step_app = typer.Typer(help="Step runs / jobs")
app.add_typer(step_app, name="step")


@step_app.command("run")
def step_run(
    ctx: typer.Context,
    step_id: str = typer.Argument(..., help="e.g. bb.stage1.crtsh"),
    engagement: str = typer.Option(..., "--engagement", "-e"),
    param: list[str] = typer.Option(None, "--param", "-p",
                                    help="key=value parameter override"),
) -> None:
    """Queue a step for an engagement."""
    eng_id = _resolve_engagement(ctx, engagement)
    params: dict = {}
    for kv in param or []:
        k, _, v = kv.partition("=")
        if k:
            params[k.strip()] = v.strip()
    with _client(ctx) as c:
        out = c.post("/steps/run",
                     json={"engagement_id": eng_id, "step_id": step_id, "params": params})
    rprint(f"[bold green]Queued[/] step {step_id} as run #{out['id']}")


@step_app.command("list")
def step_list(ctx: typer.Context, engagement: str = typer.Option(..., "--engagement", "-e")) -> None:
    eng_id = _resolve_engagement(ctx, engagement)
    with _client(ctx) as c:
        rows = c.get(f"/engagements/{eng_id}/runs")
    t = Table("id", "step_id", "stage", "mode", "status", "worker_id", "summary")
    for r in rows:
        t.add_row(str(r["id"]), r["step_id"], r.get("stage") or "-",
                  r["mode"], r["status"], r.get("worker_id") or "-",
                  (r.get("output_summary") or "-")[:60])
    console.print(t)


# ──────────────────────────── asset / finding ────────────────────────────


asset_app = typer.Typer(help="Master spreadsheet")
app.add_typer(asset_app, name="asset")


@asset_app.command("list")
def asset_list(ctx: typer.Context, engagement: str = typer.Option(..., "--engagement", "-e"),
               in_scope: bool | None = typer.Option(None, "--in-scope/--out-of-scope")) -> None:
    eng_id = _resolve_engagement(ctx, engagement)
    params: dict = {}
    if in_scope is not None:
        params["in_scope"] = "true" if in_scope else "false"
    with _client(ctx) as c:
        rows = c.get(f"/engagements/{eng_id}/assets", params=params)
    t = Table("id", "host", "ip", "env", "source", "in_scope", "risk")
    for a in rows:
        t.add_row(str(a["id"]), a["host"], a.get("ip") or "-",
                  a.get("env_type") or "-", a.get("source") or "-",
                  "yes" if a["in_scope"] else "no", str(a["risk_total"]))
    console.print(t)


finding_app = typer.Typer(help="Findings")
app.add_typer(finding_app, name="finding")


@finding_app.command("list")
def finding_list(ctx: typer.Context, engagement: str = typer.Option(..., "--engagement", "-e"),
                 severity: str | None = typer.Option(None, "--severity")) -> None:
    eng_id = _resolve_engagement(ctx, engagement)
    params = {"severity": severity} if severity else None
    with _client(ctx) as c:
        rows = c.get(f"/engagements/{eng_id}/findings", params=params)
    t = Table("id", "severity", "cvss", "title", "status")
    for f in rows:
        t.add_row(str(f["id"]), f["severity"],
                  f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "-",
                  f["title"], f["status"])
    console.print(t)


# ──────────────────────────── finalize ────────────────────────────


fin_app = typer.Typer(help="Finalize: promote artifacts to OneDrive archive")
app.add_typer(fin_app, name="finalize")


@fin_app.command("status")
def finalize_status(ctx: typer.Context,
                    engagement: str = typer.Option(..., "--engagement", "-e")) -> None:
    """Show whether the cold archive is configured for an engagement."""
    eng_id = _resolve_engagement(ctx, engagement)
    with _client(ctx) as c:
        out = c.get(f"/engagements/{eng_id}/archive-status")
    if not out["configured"]:
        rprint("[yellow]archive_root is not configured[/]"
               " (set TWISTED_ARCHIVE_ROOT to enable finalize).")
        return
    rprint("[bold green]Archive configured.[/]")
    rprint(f"  root:     {out['archive_root']}")
    rprint(f"  reports:  {out['reports_dir']}")
    rprint(f"  evidence: {out['evidence_dir']}")


@fin_app.command("finding")
def finalize_finding_cmd(
    ctx: typer.Context,
    finding_id: int = typer.Argument(...),
    engagement: str = typer.Option(..., "--engagement", "-e"),
) -> None:
    """Promote a finding's evidence to the cold archive and mark the
    finding as REPORTED."""
    eng_id = _resolve_engagement(ctx, engagement)
    with _client(ctx) as c:
        out = c.post(
            f"/engagements/{eng_id}/findings/{finding_id}/finalize",
        )
    if not out["success"]:
        rprint(f"[red]✗ finalize failed:[/] {out.get('error')}")
        raise typer.Exit(1)
    rprint(f"[bold green]✓ finalized finding #{finding_id}[/]")
    for p in out.get("archived_paths", []):
        rprint(f"  archived: {p}")
    for p in out.get("skipped", []):
        rprint(f"  [dim]skipped:  {p}[/]")


@fin_app.command("report")
def finalize_report_cmd(
    ctx: typer.Context,
    engagement: str = typer.Option(..., "--engagement", "-e"),
    paths: list[str] = typer.Argument(..., help="Report file paths to archive"),
) -> None:
    """Copy report files into the engagement's cold archive."""
    eng_id = _resolve_engagement(ctx, engagement)
    with _client(ctx) as c:
        out = c.post(
            f"/engagements/{eng_id}/finalize-report",
            json={"paths": paths},
        )
    if not out["success"]:
        rprint(f"[red]✗ finalize-report failed:[/] {out.get('error')}")
        raise typer.Exit(1)
    rprint(f"[bold green]✓ archived {len(out['archived_paths'])} file(s)[/]")
    for p in out["archived_paths"]:
        rprint(f"  → {p}")


# ──────────────────────────── token ────────────────────────────


token_app = typer.Typer(help="Worker bearer token")
app.add_typer(token_app, name="token")


@token_app.command("show")
def token_show() -> None:
    """Print the worker bearer token (creates one if missing)."""
    s = get_settings()
    s.ensure_dirs()
    rprint(ensure_token(s))


@token_app.command("path")
def token_path() -> None:
    """Print the token file path (paste into Windows worker config)."""
    rprint(str(get_settings().token_file))


@token_app.command("verify")
def token_verify(ctx: typer.Context) -> None:
    """Hit /health (open) and /workers (auth) to verify the token works."""
    with _client(ctx) as c:
        rprint(c.health())
        try:
            rprint(c.get("/workers"))
            rprint("[bold green]Token works.[/]")
        except Exception as e:  # noqa: BLE001
            rprint(f"[bold red]Token failed:[/] {e}")
            raise typer.Exit(1) from e


from . import import_ovh, labs, training  # noqa: E402

import_ovh.attach(app)
training.attach(app)
labs.attach(app)


if __name__ == "__main__":
    app()
