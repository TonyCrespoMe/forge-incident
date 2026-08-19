"""ForgeIncident command-line interface.

Commands, grouped by what they're for:

Producing a package
- `forge-incident generate SCENARIO.yaml`        — deterministic, from a YAML file + seed
- `forge-incident generate-nl "<prompt>"`         — natural-language planning (LLM optional)
- `forge-incident generate-category`              — LLM invents a brand-new scenario from a
                                                     category + difficulty (LLM required)

Running an exercise
- `forge-incident export SCENARIO.yaml`           — SIEM ingest formats (Splunk/Elastic/Sentinel)
- `forge-incident score SCENARIO.yaml SUB.json`   — grade a student submission

Browsing / introspection
- `forge-incident categories`                     — browse the scenario category taxonomy
- `forge-incident list`                           — discover scenarios in a directory
- `forge-incident plugins`                        — show loaded built-in + plugin log generators
- `forge-incident web`                            — launch the browser UI

Nothing in this module generates log content itself — it only wires
together `scenario_loader`, `llm`, and `packager`, and is responsible for
turning their exceptions into short, actionable terminal output instead
of Python tracebacks.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from forge_incident import __version__
from forge_incident.emitters import BUILTIN_EMITTERS, refresh_emitters
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
from forge_incident.scenario_categories import (
    CATEGORIES,
    DOMAINS,
    categories_in_domain,
    get_category,
    get_domain,
)
from forge_incident.scenario_loader import ScenarioLoadError, list_scenarios, load_scenario
from forge_incident.scoring import (
    SubmissionError,
    load_submission,
    render_report_markdown,
    score_submission,
)
from forge_incident.siem import EXPORTER_NAMES, UnknownExporterError, export_scenario

# Pre-joined here rather than inline in the --format help string: a call inside a
# default-argument expression is evaluated at import time anyway, and hoisting it
# keeps that explicit (ruff B008).
_EXPORTER_CHOICES = ", ".join(EXPORTER_NAMES)

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
    seed: int | None = typer.Option(
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
    prompt: str = typer.Argument(
        ..., help="Natural-language description of the scenario you want."
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="Seed (default: $FORGE_DEFAULT_SEED, else 1337)."
    ),
    llm: str = typer.Option(
        None,
        "--llm",
        help=(
            f"Planning backend to use: {', '.join(BACKEND_NAMES)} "
            "(default: $FORGE_LLM_BACKEND, else 'none')."
        ),
    ),
    difficulty: Difficulty | None = typer.Option(
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

    console.print(
        f"[bold]{backend_name}[/bold] chose template [cyan]{plan.scenario_template}[/cyan]"
    )
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
    domain: str | None = typer.Option(
        None,
        "--domain",
        help="Only show categories in this domain (see domain IDs below with no flag).",
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
        ...,
        "--category",
        help="Category ID from `forge-incident categories`, e.g. 'web-a05-injection'.",
    ),
    difficulty: Difficulty = typer.Option(
        Difficulty.INTERMEDIATE, "--difficulty", help="Target difficulty."
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="Seed (default: $FORGE_DEFAULT_SEED, else 1337)."
    ),
    llm: str = typer.Option(
        None,
        "--llm",
        help=(
            "Generation backend (required — full scenario invention needs a real LLM, "
            "unlike generate-nl's 'none' option): "
            f"{', '.join(n for n in BACKEND_NAMES if n != 'none')}."
        ),
    ),
    max_attempts: int = typer.Option(
        DEFAULT_MAX_ATTEMPTS, "--max-attempts", help="Validate/retry attempts before giving up."
    ),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"),
        "--scenarios-dir",
        help="Directory containing the few-shot example scenarios.",
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
# export — SIEM ingest formats
# --------------------------------------------------------------------------


@app.command("export")
def export_command(
    scenario_file: Path = typer.Argument(..., help="Path to a scenario YAML file."),
    formats: list[str] | None = typer.Option(
        None,
        "--format",
        "-f",
        help=(
            f"SIEM format(s) to export; repeatable. Choices: {_EXPORTER_CHOICES}. "
            "Default: all of them."
        ),
    ),
    seed: int | None = typer.Option(
        None, "--seed", help="Override the seed declared in the scenario file."
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Directory to write the export files into."
    ),
) -> None:
    """Export a scenario into SIEM ingest formats (Splunk, Elastic, Sentinel).

    Unlike `generate`, this writes loose files rather than ZIPs — you're
    feeding them to an ingest API, not handing them to a student. The
    exported data describes the same incident, with the same identifiers,
    as the raw log package for the same scenario + seed.
    """
    output_dir = output or Path(os.environ.get("FORGE_OUTPUT_DIR", "./output"))

    try:
        scenario = load_scenario(scenario_file, seed=seed)
    except ScenarioLoadError as exc:
        err_console.print(f"[bold red]Failed to load scenario:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    try:
        artifacts = export_scenario(scenario, formats)
    except UnknownExporterError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from None

    console.print(
        f"Exporting [bold]{scenario.title}[/bold] "
        f"([cyan]{scenario.scenario_id}[/cyan], seed=[cyan]{scenario.seed}[/cyan], "
        f"{scenario.event_count} events)"
    )
    for artifact in artifacts:
        destination = output_dir / artifact.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(artifact.content, encoding="utf-8")
        console.print(f"  [green]wrote[/green] {destination}")
        console.print(f"         {artifact.description}")


# --------------------------------------------------------------------------
# score — grade a student submission against ground truth
# --------------------------------------------------------------------------


@app.command("score")
def score_command(
    scenario_file: Path = typer.Argument(..., help="The scenario YAML the student worked."),
    submission_file: Path = typer.Argument(..., help="The student's completed submission.json."),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help=(
            "Seed the student's package was generated with. MUST match, or event "
            "timestamps (and therefore response-time scoring) won't line up."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the full Markdown report (and a .json sibling) to this directory.",
    ),
) -> None:
    """Score a student submission: detection coverage, false positives, response time.

    Deterministic and fully offline — no LLM involved. The same scenario
    (same seed) plus the same submission always produces the same numbers,
    so two instructors grading the same work agree by construction.
    """
    try:
        scenario = load_scenario(scenario_file, seed=seed)
    except ScenarioLoadError as exc:
        err_console.print(f"[bold red]Failed to load scenario:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    try:
        submission = load_submission(submission_file)
    except SubmissionError as exc:
        err_console.print(f"[bold red]Failed to load submission:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    if submission.scenario_id and submission.scenario_id != scenario.scenario_id:
        err_console.print(
            f"[yellow]Warning:[/yellow] submission says scenario_id="
            f"'{submission.scenario_id}' but you're scoring against "
            f"'{scenario.scenario_id}'. Scoring anyway — check you picked the right file."
        )

    report = score_submission(scenario, submission)

    table = Table(title=f"Score: {submission.analyst} — {scenario.title}")
    table.add_column("Metric")
    table.add_column("Result", justify="right")
    table.add_row(
        "Detection coverage",
        f"{report.coverage_pct:.0f}%  ({report.detected_count}/{report.total_opportunities})",
    )
    table.add_row(
        "Precision",
        f"{report.precision_pct:.0f}%  "
        f"({report.false_positive_count + report.unknown_event_id_count} false positive(s))",
    )
    ttfd = report.time_to_first_detection_seconds
    table.add_row(
        "Time to first detection", "n/a" if ttfd is None else f"{ttfd / 60:.0f} min"
    )
    mean_latency = report.mean_latency_seconds
    table.add_row(
        "Mean detection latency", "n/a" if mean_latency is None else f"{mean_latency / 60:.0f} min"
    )
    console.print(table)

    if report.missed_event_ids:
        console.print(
            f"[yellow]Missed {len(report.missed_event_ids)} opportunity(ies):[/yellow] "
            + ", ".join(report.missed_event_ids)
        )

    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        stem = f"{scenario.scenario_id}-{slugify_name(submission.analyst)}-score"
        md_path = output / f"{stem}.md"
        json_path = output / f"{stem}.json"
        md_path.write_text(render_report_markdown(report, scenario), encoding="utf-8")
        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"  [green]report[/green]: {md_path}")
        console.print(f"  [green]data[/green]:   {json_path}")


def slugify_name(value: str) -> str:
    """Filesystem-safe slug for report filenames."""
    keep = [ch.lower() if ch.isalnum() else "-" for ch in value.strip()]
    slug = "".join(keep).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "anonymous"


# --------------------------------------------------------------------------
# plugins — show what custom log generators are loaded
# --------------------------------------------------------------------------


@app.command("plugins")
def plugins_command(
    plugins_dir: Path | None = typer.Option(
        None,
        "--plugins-dir",
        help="Directory of plugin .py files (default: $FORGE_PLUGINS_DIR, else ./plugins).",
    ),
) -> None:
    """List built-in and plugin log generators, and report any that failed to load."""
    discovery = refresh_emitters(plugins_dir=str(plugins_dir) if plugins_dir else None)

    builtin_table = Table(title="Built-in log generators")
    builtin_table.add_column("Log source", style="cyan")
    builtin_table.add_column("Class")
    for emitter in BUILTIN_EMITTERS:
        source = getattr(emitter, "log_source", None)
        builtin_table.add_row(source.value if source else "-", type(emitter).__name__)
    console.print(builtin_table)

    if discovery.loaded:
        plugin_table = Table(title="Plugin log generators")
        plugin_table.add_column("Log source", style="cyan")
        plugin_table.add_column("Class")
        plugin_table.add_column("Loaded from")
        for origin, class_name in discovery.loaded:
            matching = next(
                (e for e in discovery.emitters if type(e).__name__ == class_name), None
            )
            source = ""
            if matching is not None:
                builtin_source = getattr(matching, "log_source", None)
                source = (
                    builtin_source.value
                    if builtin_source
                    else getattr(matching, "log_source_name", "")
                )
            plugin_table.add_row(source or "-", class_name, origin)
        console.print(plugin_table)
    else:
        console.print(
            "\nNo plugins loaded. Drop a .py file defining an Emitter subclass into "
            "[cyan]./plugins/[/cyan] (or set $FORGE_PLUGINS_DIR) — see CONTRIBUTING.md."
        )

    if discovery.errors:
        err_console.print("\n[bold red]Plugins that failed to load:[/bold red]")
        for origin, message in discovery.errors:
            err_console.print(f"  [red]{origin}[/red]: {message}")


# --------------------------------------------------------------------------
# web — launch the browser UI
# --------------------------------------------------------------------------


@app.command("web")
def web_command(
    port: int = typer.Option(8501, "--port", help="Port to serve the UI on."),
    scenarios_dir: Path = typer.Option(
        Path("scenarios"), "--scenarios-dir", help="Directory of scenarios to browse/edit."
    ),
) -> None:
    """Launch the ForgeIncident web UI in your browser.

    Requires the optional extra:  pip install "forge-incident[webui]"
    """
    try:
        import streamlit  # noqa: F401
    except ImportError:
        err_console.print(
            "[bold red]The web UI requires Streamlit.[/bold red] Install it with:\n"
            '  pip install "forge-incident[webui]"'
        )
        raise typer.Exit(code=1) from None

    import subprocess

    app_path = Path(__file__).parent / "webui" / "app.py"
    env = {**os.environ, "FORGE_SCENARIOS_DIR": str(scenarios_dir)}
    console.print(f"Starting ForgeIncident web UI on [cyan]http://localhost:{port}[/cyan] …")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(app_path),
            "--server.port",
            str(port),
        ],
        env=env,
        check=False,
    )


# --------------------------------------------------------------------------
# shared output helper
# --------------------------------------------------------------------------


def _print_result(result) -> None:
    console.print(f"  [green]student package[/green]:    {result.student_zip}")
    console.print(f"  [green]instructor package[/green]: {result.instructor_zip}")
    console.print(f"  {result.artifact_count} log artifact(s) rendered.")


if __name__ == "__main__":
    app()
