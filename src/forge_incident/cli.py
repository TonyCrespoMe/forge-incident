"""ForgeIncident command-line interface.

Three commands, matching the project's three ways to produce a package:

- `forge-incident generate SCENARIO.yaml`       — deterministic, from a YAML file + seed
- `forge-incident generate-nl "<prompt>"`        — natural-language planning (LLM optional)
- `forge-incident list`                          — discover scenarios in a directory

Nothing in this module generates log content itself — it only wires
together `scenario_loader`, `llm`, and `packager`, and is responsible for
turning their exceptions into short, actionable terminal output instead
of Python tracebacks.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from forge_incident import __version__
from forge_incident.llm import (
    BACKEND_NAMES,
    LLMBackendError,
    build_scenario_from_plan,
    get_backend,
    resolve_template_path,
)
from forge_incident.models import Difficulty
from forge_incident.packager import build_packages
from forge_incident.scenario_loader import ScenarioLoadError, list_scenarios, load_scenario

app = typer.Typer(
    name="forge-incident",
    no_args_is_help=True,
    add_completion=False,
    help=(
        "Generate realistic, deterministic student + instructor DFIR investigation "
        "packages. Works fully offline by default."
    ),
)
console = Console()
err_console = Console(stderr=True)


# --------------------------------------------------------------------------
# .env loading — no python-dotenv dependency, just a few KEY=VALUE lines.
# --------------------------------------------------------------------------


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


@app.callback()
def main() -> None:
    """Loaded once before every command."""
    _load_dotenv()


@app.command()
def version() -> None:
    """Print the ForgeIncident version."""
    console.print(f"forge-incident {__version__}")


# --------------------------------------------------------------------------
# generate — deterministic, from a YAML scenario file
# --------------------------------------------------------------------------


@app.command()
def generate(
    scenario_file: Path = typer.Argument(..., help="Path to a scenario YAML file."),
    seed: Optional[int] = typer.Option(
        None, "--seed", help="Override the seed declared in the scenario file."
    ),
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Directory to write the student/instructor ZIPs into.",
    ),
) -> None:
    """Generate a package deterministically from a YAML scenario file."""
    output_dir = output or Path(os.environ.get("FORGE_OUTPUT_DIR", "./output"))

    try:
        scenario = load_scenario(scenario_file, seed=seed)
    except ScenarioLoadError as exc:
        err_console.print(f"[bold red]Failed to load scenario:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    console.print(
        f"Loaded [bold]{scenario.title}[/bold] "
        f"([cyan]{scenario.scenario_id}[/cyan], seed=[cyan]{scenario.seed}[/cyan], "
        f"{scenario.event_count} events)"
    )

    result = build_packages(scenario, output_dir, source_path=scenario_file)
    _print_result(result)


# --------------------------------------------------------------------------
# generate-nl — natural-language planning, LLM optional
# --------------------------------------------------------------------------


@app.command("generate-nl")
def generate_nl(
    prompt: str = typer.Argument(..., help="Natural-language description of the scenario you want."),
    seed: Optional[int] = typer.Option(
        None, "--seed", help="Seed (default: $FORGE_DEFAULT_SEED, else 1337)."
    ),
    llm: str = typer.Option(
        None,
        "--llm",
        help=f"Planning backend to use: {', '.join(BACKEND_NAMES)} (default: $FORGE_LLM_BACKEND, else 'none').",
    ),
    difficulty: Optional[Difficulty] = typer.Option(
        None, "--difficulty", help="Force a difficulty instead of letting the backend infer one."
    ),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"), "--scenarios-dir", help="Directory of scenario templates to choose from."
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Directory to write the student/instructor ZIPs into."
    ),
) -> None:
    """Generate a package from a natural-language prompt.

    The chosen backend only ever picks among the scenario templates in
    `--scenarios-dir` and sets a difficulty/title/tags — it never invents
    log content (see llm/base.py). The default backend, 'none', does this
    with zero network access and zero extra dependencies.
    """
    resolved_seed = seed if seed is not None else int(os.environ.get("FORGE_DEFAULT_SEED", 1337))
    backend_name = llm or os.environ.get("FORGE_LLM_BACKEND", "none")
    output_dir = output or Path(os.environ.get("FORGE_OUTPUT_DIR", "./output"))

    try:
        backend = get_backend(backend_name)
    except LLMBackendError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    if not backend.is_available():
        err_console.print(
            f"[bold red]The '{backend_name}' backend isn't available[/bold red] "
            f"(missing dependency, API key, or unreachable). Try [bold]--llm none[/bold] "
            f"to generate fully offline, or check your .env against .env.example."
        )
        raise typer.Exit(code=1)

    try:
        plan = backend.plan_scenario(
            prompt, seed=resolved_seed, difficulty=difficulty, scenarios_dir=scenarios_dir
        )
    except LLMBackendError as exc:
        err_console.print(f"[bold red]Planning failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    console.print(f"[bold]{backend_name}[/bold] chose template [cyan]{plan.scenario_template}[/cyan]")
    if plan.rationale:
        console.print(f"  rationale: {plan.rationale}")

    try:
        scenario = build_scenario_from_plan(plan, scenarios_dir, seed=resolved_seed)
    except LLMBackendError as exc:
        err_console.print(f"[bold red]Failed to build scenario from plan:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    console.print(
        f"Generated [bold]{scenario.title}[/bold] "
        f"([cyan]{scenario.scenario_id}[/cyan], seed=[cyan]{scenario.seed}[/cyan], "
        f"{scenario.event_count} events)"
    )

    template_path = resolve_template_path(plan.scenario_template, scenarios_dir)
    result = build_packages(scenario, output_dir, source_path=template_path)
    _print_result(result)


# --------------------------------------------------------------------------
# list — discover scenarios in a directory
# --------------------------------------------------------------------------


@app.command("list")
def list_command(
    scenarios_dir: Path = typer.Option(
        Path("scenarios"), "--scenarios-dir", help="Directory to scan for scenario YAML files."
    ),
) -> None:
    """List and validate every scenario in a directory."""
    try:
        summaries = list_scenarios(scenarios_dir)
    except ScenarioLoadError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    if not summaries:
        console.print(f"No scenario files found in [cyan]{scenarios_dir}[/cyan].")
        return

    table = Table(title=f"Scenarios in {scenarios_dir}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Difficulty")
    table.add_column("Events", justify="right")
    table.add_column("Tags")
    table.add_column("Status")

    for s in summaries:
        if s.is_valid:
            table.add_row(
                s.scenario_id,
                s.title,
                s.difficulty,
                str(s.event_count),
                ", ".join(s.tags),
                "[green]ok[/green]",
            )
        else:
            table.add_row(
                s.scenario_id, "-", "-", "-", "-", f"[bold red]invalid[/bold red]: {s.error}"
            )

    console.print(table)


# --------------------------------------------------------------------------
# shared output helper
# --------------------------------------------------------------------------


def _print_result(result) -> None:
    console.print(f"  [green]student package[/green]:    {result.student_zip}")
    console.print(f"  [green]instructor package[/green]: {result.instructor_zip}")
    console.print(f"  {result.artifact_count} log artifact(s) rendered.")


if __name__ == "__main__":
    app()
