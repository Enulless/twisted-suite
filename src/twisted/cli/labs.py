"""Practice-lab CLI commands.

Attached by ``cli.__main__`` via ``labs.attach(app)``::

    twisted lab list                       # show all labs + status
    twisted lab status dvwa
    twisted lab up dvwa [--port 18181]
    twisted lab down dvwa
    twisted lab logs dvwa [--tail 200]
"""

from __future__ import annotations

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

lab_app = typer.Typer(help="Practice labs (Docker)")
console = Console()


def _client(ctx: typer.Context):
    from .__main__ import _client as _c
    return _c(ctx)


@lab_app.command("list")
def lab_list(ctx: typer.Context) -> None:
    """List every registered lab with current state."""
    with _client(ctx) as c:
        rows = c.get("/labs")
    t = Table("id", "state", "target", "name")
    for r in rows:
        state_color = {
            "up": "green", "down": "dim", "partial": "yellow", "unknown": "red",
        }.get(r["state"], "white")
        t.add_row(
            r["id"],
            f"[{state_color}]{r['state']}[/{state_color}]",
            r["target_url"],
            r["name"],
        )
    console.print(t)


@lab_app.command("status")
def lab_status_cmd(ctx: typer.Context, lab: str = typer.Argument(...)) -> None:
    with _client(ctx) as c:
        r = c.get(f"/labs/{lab}")
    rprint(f"[bold cyan]{r['id']}[/]: {r['name']}")
    rprint(f"  state:  [bold]{r['state']}[/]")
    rprint(f"  target: {r['target_url']}")
    if r.get("services"):
        rprint("  services:")
        for name, st in r["services"].items():
            rprint(f"    - {name}: {st}")


@lab_app.command("up")
def lab_up_cmd(
    ctx: typer.Context,
    lab: str = typer.Argument(...),
    port: int | None = typer.Option(None, "--port", "-p"),
    wait: int = typer.Option(60, "--wait", "-w",
                              help="Pass --wait to docker compose"),
) -> None:
    """Bring a lab up (docker compose up -d --wait)."""
    payload = {"port": port, "wait_seconds": wait}
    with _client(ctx) as c:
        r = c.post(f"/labs/{lab}/up", json=payload)
    if not r["available"]:
        rprint(f"[red]Docker not available on the engine host:[/] {r['error']}")
        raise typer.Exit(2)
    if r["success"]:
        rprint(f"[bold green]✓[/] {lab} up (state={r['state']})")
        if r.get("output"):
            console.print(r["output"], style="dim")
    else:
        rprint(f"[red]✗ {lab} failed to start:[/] {r.get('error')}")
        if r.get("output"):
            console.print(r["output"], style="dim")
        raise typer.Exit(1)


@lab_app.command("down")
def lab_down_cmd(
    ctx: typer.Context,
    lab: str = typer.Argument(...),
    keep_volumes: bool = typer.Option(False, "--keep-volumes",
                                       help="Don't pass -v to docker compose down"),
) -> None:
    """Tear a lab down (docker compose down -v by default)."""
    params = {"keep_volumes": "true"} if keep_volumes else None
    with _client(ctx) as c:
        r = c.post(f"/labs/{lab}/down", params=params)
    if r["success"]:
        rprint(f"[bold green]✓[/] {lab} down")
    else:
        rprint(f"[red]✗ {lab} down failed:[/] {r.get('error')}")
        raise typer.Exit(1)


@lab_app.command("logs")
def lab_logs_cmd(
    ctx: typer.Context,
    lab: str = typer.Argument(...),
    tail: int = typer.Option(100, "--tail", "-n"),
) -> None:
    """Tail recent logs from a running lab."""
    with _client(ctx) as c:
        r = c.get(f"/labs/{lab}/logs", params={"tail": tail})
    if not r["available"]:
        rprint(f"[red]Docker not available:[/] {r.get('error')}")
        raise typer.Exit(2)
    rprint(r["output"])


def attach(app: typer.Typer) -> None:
    app.add_typer(lab_app, name="lab")
