"""ForgeIncident command-line interface.

Five commands, matching the project's ways to produce a package or browse
what's available:

- `forge-incident generate SCENARIO.yaml`        — deterministic, from a YAML file + seed
- `forge-incident generate-nl "<prompt>"`         — natural-language planning (LLM optional)
- `forge-incident generate-category`              — LLM invents a brand-new scenario from a
                                                     category + difficulty (LLM required)
- `forge-incident categories`                     — browse the scenario category taxonomy
- `forge-incident list`                           — discover scenarios in a directory

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
    DEFAULT_MAX_ATTEMPTS,
    LLMBackendError,
    build_scenario_from_plan,
    generate_new_scenario,
    get_backend,
    resolve_template_path,
)
from forge_incident.models import Difficulty
from forge_incident.packager import build_packages
from forge_incident.scenario_categories import CATEGORIES, DOMAINS, categories_in_domain, get_category, get_domain
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
# categories — browse the scenario category taxonomy
# --------------------------------------------------------------------------


@app.command("categories")
def categories_command(
    domain: Optional[str] = typer.Option(
        None, "--domain", help="Only show categories in this domain (see domain IDs below with no flag)."
    ),
) -> None:
    """List the scenario category taxonomy used by `generate-category`.

    Run with no flags to see all domains and every category within them.
    """
    if domain is not None:
        try:
            get_domain(domain)
        except KeyError as exc:
            err_console.print(f"[bold red]{exc}[/bold red]")
            raise typer.Exit(code=1) from None
        domains_to_show = [d for d in DOMAINS if d.id == domain]
    else:
        domains_to_show = list(DOMAINS)

    for d in domains_to_show:
        cats = categories_in_domain(d.id)
        table = Table(title=f"{d.name}  ({d.id})", caption=d.description)
        table.add_column("Category ID", style="cyan")
        table.add_column("Name")
        table.add_column("Source")
        for c in cats:
            table.add_row(c.id, c.name, c.source)
        console.print(table)
    console.print(f"\n{len(CATEGORIES)} categories across {len(DOMAINS)} domains.")


# --------------------------------------------------------------------------
# generate-category — LLM invents a brand-new scenario from a category
# --------------------------------------------------------------------------


def _choose_example_scenario(category, scenarios_dir: Path) -> Path:
    """Pick whichever bundled scenario best matches this category's shape as a
    few-shot format example (the model is told not to reuse its story)."""
    cloud_sources = {"gcp_audit", "aws_cloudtrail", "azure_activity"}
    if set(category.primary_log_sources) & cloud_sources:
        candidate = scenarios_dir / "gcp_key_compromise.yaml"
    else:
        candidate = scenarios_dir / "phishing_to_exfil.yaml"
    if candidate.is_file():
        return candidate
    # Fall back to whatever's first available, so this never hard-fails just
    # because a bundled filename changed.
    yaml_files = sorted(scenarios_dir.glob("*.yaml")) + sorted(scenarios_dir.glob("*.yml"))
    if not yaml_files:
        raise LLMBackendError(f"No example scenario files found under {scenarios_dir}")
    return yaml_files[0]


@app.command("generate-category")
def generate_category(
    category: str = typer.Option(
        ..., "--category", help="Category ID from `forge-incident categories`, e.g. 'web-a05-injection'."
    ),
    difficulty: Difficulty = typer.Option(
        Difficulty.INTERMEDIATE, "--difficulty", help="Target difficulty."
    ),
    seed: Optional[int] = typer.Option(
        None, "--seed", help="Seed (default: $FORGE_DEFAULT_SEED, else 1337)."
    ),
    llm: str = typer.Option(
        None,
        "--llm",
        help=(
            "Generation backend (required — full scenario invention needs a real LLM, "
            f"unlike generate-nl's 'none' option): {', '.join(n for n in BACKEND_NAMES if n != 'none')}."
        ),
    ),
    max_attempts: int = typer.Option(
        DEFAULT_MAX_ATTEMPTS, "--max-attempts", help="Validate/retry attempts before giving up."
    ),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"), "--scenarios-dir", help="Directory containing the few-shot example scenarios."
    ),
    save_dir: Path = typer.Option(
        Path("scenarios/generated"), "--save-dir", help="Where to save the accepted generated YAML."
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Directory to write the student/instructor ZIPs into."
    ),
) -> None:
    """Generate a brand-new scenario from a category + difficulty using a real LLM.

    Unlike `generate-nl` (which only ever picks among existing YAML
    templates — see llm/base.py's Core Architecture Rule), this command
    asks the chosen LLM backend to invent an entirely new scenario, then
    validates it through the exact same schema every hand-written
    scenario goes through, retrying on failure. The resulting instructor
    package is explicitly flagged as LLM-generated and lists any
    heuristic consistency warnings — review it before classroom use.
    """
    try:
        category_obj = get_category(category)
    except KeyError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    resolved_seed = seed if seed is not None else int(os.environ.get("FORGE_DEFAULT_SEED", 1337))
    backend_name = llm or os.environ.get("FORGE_LLM_BACKEND", "none")
    output_dir = output or Path(os.environ.get("FORGE_OUTPUT_DIR", "./output"))

    if backend_name == "none":
        err_console.print(
            "[bold red]generate-category requires a real LLM backend[/bold red] — pass "
            f"--llm (one of: {', '.join(n for n in BACKEND_NAMES if n != 'none')}). The "
            "'none' backend only supports generate/generate-nl (template selection), not "
            "brand-new scenario invention."
        )
        raise typer.Exit(code=1)

    try:
        backend = get_backend(backend_name)
    except LLMBackendError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    if not backend.is_available():
        err_console.print(
            f"[bold red]The '{backend_name}' backend isn't available[/bold red] "
            "(missing dependency, API key, or unreachable). Check your .env against .env.example."
        )
        raise typer.Exit(code=1)

    try:
        example_path = _choose_example_scenario(category_obj, scenarios_dir)
    except LLMBackendError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    console.print(
        f"Generating [bold]{category_obj.name}[/bold] ([cyan]{category_obj.id}[/cyan], "
        f"domain: {category_obj.domain}) at difficulty [cyan]{difficulty.value}[/cyan] "
        f"using [bold]{backend_name}[/bold] (up to {max_attempts} attempt(s))..."
    )

    try:
        result = generate_new_scenario(
            backend,
            category_id=category,
            difficulty=difficulty,
            seed=resolved_seed,
            example_scenario_path=example_path,
            max_attempts=max_attempts,
        )
    except LLMBackendError as exc:
        err_console.print(f"[bold red]Generation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    console.print(
        f"[green]Generated and validated[/green] on attempt {result.attempts}/{max_attempts}: "
        f"[bold]{result.scenario.title}[/bold] ({result.scenario.event_count} events)"
    )
    if result.warnings:
        console.print("[yellow]Consistency check warnings (review before classroom use):[/yellow]")
        for w in result.warnings:
            console.print(f"  - {w}")

    save_dir.mkdir(parents=True, exist_ok=True)
    saved_path = save_dir / f"{result.scenario.scenario_id}.yaml"
    saved_path.write_text(result.yaml_text, encoding="utf-8")
    console.print(f"Saved generated YAML to [cyan]{saved_path}[/cyan]")

    package_result = build_packages(
        result.scenario,
        output_dir,
        source_path=saved_path,
        llm_generated_by=backend_name,
        generation_warnings=result.warnings,
    )
    _print_result(package_result)


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
