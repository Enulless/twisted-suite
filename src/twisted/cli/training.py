"""Training-mode CLI commands.

Attached by ``cli.__main__`` via ``training.attach(app)``::

    twisted train list                       # all lessons w/ progress
    twisted train show <step_id>             # render a lesson to the terminal
    twisted train quiz <step_id>             # interactive quiz
    twisted train extract --bb <docx>        # rebuild lessons from docx
    twisted train progress                   # per-lesson progress summary

The ``extract`` command runs locally (does not touch the engine) so
operators can rebuild lessons without the engine running.
"""

from __future__ import annotations

import getpass
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.table import Table

train_app = typer.Typer(help="Training mode: lessons, quizzes, progress")
console = Console()


def _user_default() -> str:
    try:
        return getpass.getuser() or "default"
    except Exception:  # noqa: BLE001
        return "default"


@train_app.command("list")
def train_list(
    ctx: typer.Context,
    procedure: str | None = typer.Option(None, "--procedure", "-p",
                                          help="Filter: bb / wp_stress / wifi"),
    user: str = typer.Option(_user_default(), "--user", "-u"),
) -> None:
    """List every available lesson with completion status for ``user``."""
    from .__main__ import _client
    params: dict = {"user": user}
    if procedure:
        params["procedure"] = procedure
    with _client(ctx) as c:
        rows = c.get("/training", params=params)
    if not rows:
        rprint("[dim]No lessons found.[/]")
        return
    t = Table("step_id", "procedure", "stage", "title", "quiz?", "score", "done")
    for r in rows:
        score = (f"{(r['last_score'] or 0):.0%}" if r.get("last_score") is not None
                 else "-")
        t.add_row(
            r["step_id"], r["procedure"], r.get("stage") or "-",
            r["title"][:50],
            "yes" if r["has_quiz"] else "-",
            score,
            "✓" if r.get("completed") else "",
        )
    console.print(t)


@train_app.command("show")
def train_show(
    ctx: typer.Context,
    step_id: str = typer.Argument(..., help="e.g. bb.stage1.crtsh"),
    user: str = typer.Option(_user_default(), "--user", "-u"),
) -> None:
    """Render a lesson markdown to the terminal."""
    from .__main__ import _client
    with _client(ctx) as c:
        lsn = c.get(f"/training/{step_id}", params={"user": user})
    rprint(f"[bold cyan]# {lsn['title']}[/]")
    rprint(f"[dim]{lsn['step_id']} · {lsn['procedure']} · stage={lsn.get('stage') or '-'}"
           f" · ~{lsn.get('estimated_minutes') or '?'} min[/]\n")
    if lsn.get("body"):
        console.print(Markdown(lsn["body"]))
    if lsn.get("quiz"):
        rprint(
            f"\n[bold yellow]A quiz is available.[/] "
            f"Run: [bold]twisted train quiz {step_id}[/]"
        )
    if lsn.get("progress"):
        p = lsn["progress"]
        rprint(f"\n[dim]Last attempt:[/] score={p['score']:.0%} "
               f"passed={p['passed']} at {p['completed_at']}")


@train_app.command("quiz")
def train_quiz(
    ctx: typer.Context,
    step_id: str = typer.Argument(..., help="e.g. bb.stage1.crtsh"),
    user: str = typer.Option(_user_default(), "--user", "-u"),
) -> None:
    """Interactive quiz for a lesson. Prompts for each question, then
    posts the responses to the engine for grading + persistence."""
    from .__main__ import _client
    with _client(ctx) as c:
        lsn = c.get(f"/training/{step_id}", params={"user": user})
        quiz = lsn.get("quiz")
        if not quiz:
            rprint(f"[red]No quiz available for {step_id}[/]")
            raise typer.Exit(1)

        rprint(f"[bold cyan]Quiz:[/] {quiz['title']} "
               f"({quiz['pass_threshold']:.0%} to pass)")
        responses: dict[str, str] = {}
        for i, q in enumerate(quiz["questions"], start=1):
            rprint(f"\n[bold]Q{i}.[/] {q['prompt'].strip()}")
            if q["type"] == "multiple_choice":
                for key, val in q["choices"].items():
                    rprint(f"  [bold]{key}.[/] {val}")
                ans = Prompt.ask(
                    "Your answer", default="",
                    choices=list(q["choices"].keys()) + [""],
                    show_choices=False,
                )
            else:
                ans = Prompt.ask("Your answer", default="")
            responses[q["id"]] = ans

        result = c.post(f"/training/{step_id}/quiz/submit",
                        json={"user": user, "responses": responses})

    rprint(
        f"\n[bold {'green' if result['passed'] else 'red'}]"
        f"Score: {result['correct_count']}/{result['total']} "
        f"({result['score']:.0%}) — {'PASS' if result['passed'] else 'FAIL'}[/]"
    )
    for pq in result["per_question"]:
        marker = "[green]✓[/]" if pq["correct"] else "[red]✗[/]"
        rprint(f"  {marker} {pq['question_id']}: "
               f"answered={pq['response']!r}, expected={pq['expected']!r}")
        if pq.get("explain"):
            rprint(f"    [dim]{pq['explain'].strip()}[/]")


@train_app.command("progress")
def train_progress(
    ctx: typer.Context,
    user: str = typer.Option(_user_default(), "--user", "-u"),
) -> None:
    """Per-lesson completion summary for ``user``."""
    from .__main__ import _client
    with _client(ctx) as c:
        rows = c.get("/training", params={"user": user})
    by_proc: dict[str, list] = {}
    for r in rows:
        by_proc.setdefault(r["procedure"], []).append(r)
    for proc, items in sorted(by_proc.items()):
        completed = sum(1 for it in items if it.get("completed"))
        total = len(items)
        attempted = sum(1 for it in items if it.get("last_score") is not None)
        rprint(
            f"[bold cyan]{proc}[/]: {completed}/{total} completed "
            f"({attempted} attempted)"
        )


@train_app.command("extract")
def train_extract(
    bb: Path | None = typer.Option(None, "--bb", help="bug_bounty_procedure.docx"),
    wp: Path | None = typer.Option(None, "--wp", help="wp_stress_procedure.docx"),
    wifi: Path | None = typer.Option(None, "--wifi", help="wifi_pentest_methodology.docx"),
    dest: Path = typer.Option(
        Path(__file__).resolve().parent.parent / "training" / "lessons",
        "--dest", help="Output directory for lesson .md files",
    ),
) -> None:
    """Rebuild lesson markdown from one or more procedure docx files.

    Pass at least one of --bb / --wp / --wifi. The corresponding
    procedure must be loadable via the standard procedure search path.
    """
    from ..core.procedures import ProcedureLoader
    from ..training.extractor import extract_one

    docx_paths: dict[str, Path] = {}
    if bb is not None:
        docx_paths["bb"] = bb
    if wp is not None:
        docx_paths["wp_stress"] = wp
    if wifi is not None:
        docx_paths["wifi"] = wifi
    if not docx_paths:
        rprint("[red]Provide at least one of --bb / --wp / --wifi[/]")
        raise typer.Exit(1)

    procs = ProcedureLoader()
    procs.all()
    dest.mkdir(parents=True, exist_ok=True)
    for proc_id, path in docx_paths.items():
        if not path.exists():
            rprint(f"[red]{path} not found[/]")
            raise typer.Exit(2)
        report = extract_one(proc_id, path, dest, procs)
        rprint(
            f"[green]✓[/] {proc_id}: wrote {len(report.lessons_written)} lessons "
            f"({report.matched} matched, {report.placeholder} placeholder)"
        )


def attach(app: typer.Typer) -> None:
    app.add_typer(train_app, name="train")
