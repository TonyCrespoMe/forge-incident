"""Abstract interface for ForgeIncident's optional LLM planning backends.

Core architecture rule (never violate): an LLM, if configured at all, is
used ONLY to turn a natural-language prompt into a small, structured
`ScenarioPlan` — which bundled scenario template best matches the
request, an optional difficulty/title override, and optional searchable
tags. It never invents timestamps, IP addresses, hashes, hostnames, or
log content. Those always come from a template `Scenario` that already
passed full `scenario_loader` validation, so a package planned by Claude,
by Ollama, or by the zero-dependency `none` backend is exactly as
internally consistent and exactly as reproducible from its seed as one
loaded straight from YAML with `--from-yaml`.

This also means ForgeIncident works fully offline by construction: the
`none` backend implements this same interface with no network calls and
no third-party dependency, and is the default (`FORGE_LLM_BACKEND=none`).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, Field

from forge_incident.models import Difficulty, Scenario
from forge_incident.scenario_loader import ScenarioLoadError, load_scenario

__all__ = [
    "LLMBackend",
    "LLMBackendError",
    "ScenarioPlan",
    "available_templates",
    "build_scenario_from_plan",
    "extract_json_object",
    "resolve_template_path",
]


class LLMBackendError(Exception):
    """Raised when a backend cannot produce, reach, or parse a scenario plan."""


def available_templates(scenarios_dir: str | Path = "scenarios") -> list[str]:
    """Filename stems of bundled scenario templates a plan may choose from.

    e.g. `scenarios/phishing_to_exfil.yaml` -> `"phishing_to_exfil"`.
    """
    directory = Path(scenarios_dir)
    if not directory.is_dir():
        return []
    stems = {p.stem for p in directory.glob("*.yml")} | {p.stem for p in directory.glob("*.yaml")}
    return sorted(stems)


class ScenarioPlan(BaseModel):
    """A small, fully-typed plan for turning a template into a Scenario.

    Deliberately NOT a full `Scenario` — no timestamps, IPs, hashes, or
    timeline. It records only the handful of decisions an LLM (or the
    rule-based `none` backend) is trusted to make from a natural-language
    prompt. By design a plan cannot rename the organization or any actor:
    a template's org/actor/host/email fields are mutually consistent by
    construction (an actor's email domain matches the org domain, a
    host's domain-join status matches the story, etc.), and partially
    renaming them here would risk silently breaking that consistency —
    exactly what the Core Architecture Rule forbids. If you want a
    scenario about a different fictional company, write a new template.
    """

    scenario_template: str = Field(
        ..., description="Filename stem of a scenario under scenarios/, e.g. 'phishing_to_exfil'"
    )
    difficulty: Difficulty | None = Field(
        default=None, description="Overrides the template's own difficulty label, if set"
    )
    title_override: str | None = None
    emphasis_tags: list[str] = Field(
        default_factory=list, description="Extra tags merged into the template's own tags"
    )
    original_prompt: str = ""
    rationale: str = Field(
        default="", description="Human-readable explanation of why this plan was chosen"
    )
    backend_name: str = "unknown"


class LLMBackend(ABC):
    """Common interface every LLM planning backend implements."""

    name: ClassVar[str] = "base"

    def is_available(self) -> bool:
        """Cheap, side-effect-free check of whether this backend can run.

        Must not raise — return False on missing dependency/config/network
        rather than letting the caller crash. `cli.py` uses this to give a
        friendly error (e.g. "pip install forge-incident[claude]") before
        attempting a real call.
        """
        return True

    @abstractmethod
    def plan_scenario(
        self,
        prompt: str,
        *,
        seed: int,
        difficulty: Difficulty | None = None,
        scenarios_dir: str | Path = "scenarios",
    ) -> ScenarioPlan:
        """Turn a natural-language prompt into a structured ScenarioPlan."""

    def generate_scenario_text(
        self, *, system_prompt: str, user_prompt: str, max_tokens: int = 4096
    ) -> str:
        """Raw text completion for full brand-new-scenario YAML generation.

        Unlike `plan_scenario` (a small, narrowly-typed choice among
        *existing* templates — see the Core Architecture Rule at the top
        of this file), this is the one place a backend is trusted to
        freely invent an entire scenario: organization, actors, hosts,
        timeline, MITRE mappings, all of it. It is used ONLY by the
        `generate-category` CLI flow (see `llm/scenario_generator.py`,
        which builds `system_prompt`/`user_prompt` and runs the resulting
        YAML through the exact same `scenario_loader` validation every
        hand-written scenario goes through, with a validate/retry loop).
        `generate`/`generate-nl` never call this — those commands only
        ever use `plan_scenario`, so their determinism guarantee is
        untouched by this method's existence.

        The default implementation raises: not every backend can support
        this well (see `llm/none.py`, which explicitly cannot — genuine
        scenario invention needs real model creativity, not keyword
        matching). Backends that do support it (claude/openai/gemini/
        grok/ollama) override this.
        """
        raise LLMBackendError(
            f"The '{self.name}' backend does not support brand-new scenario generation "
            "(generate-category). Use --llm claude/openai/gemini/grok/ollama instead."
        )


def resolve_template_path(template: str, scenarios_dir: str | Path = "scenarios") -> Path:
    """Resolve a template name (e.g. 'phishing_to_exfil') to its YAML file.

    Raises `LLMBackendError` (with the list of what IS available) if
    neither a `.yaml` nor `.yml` file exists for it — the same error
    shape whether the caller is a plan-building backend or `cli.py`.
    """
    directory = Path(scenarios_dir)
    candidate = directory / f"{template}.yaml"
    if candidate.is_file():
        return candidate
    candidate = directory / f"{template}.yml"
    if candidate.is_file():
        return candidate
    known = available_templates(directory)
    raise LLMBackendError(
        f"Scenario template {template!r} not found in {directory}. Available templates: {known}"
    )


def build_scenario_from_plan(
    plan: ScenarioPlan,
    scenarios_dir: str | Path = "scenarios",
    *,
    seed: int | None = None,
) -> Scenario:
    """Deterministically instantiate a concrete `Scenario` from a plan.

    Loads the plan's chosen template exactly as `scenario_loader.load_scenario`
    would (full validation, seeded jitter), then applies only the plan's
    additive/cosmetic overrides (title, difficulty label, extra tags) via
    a single `model_copy`. Nothing about a template's actors, hosts,
    timeline, or identifiers is ever touched here.
    """
    candidate = resolve_template_path(plan.scenario_template, scenarios_dir)

    try:
        scenario = load_scenario(candidate, seed=seed)
    except ScenarioLoadError as exc:
        raise LLMBackendError(f"Failed to load template {candidate}: {exc}") from exc

    updates: dict = {}
    if plan.title_override:
        updates["title"] = plan.title_override
    if plan.difficulty is not None:
        updates["difficulty"] = plan.difficulty
    if plan.emphasis_tags:
        # Preserve order, drop duplicates.
        updates["tags"] = list(dict.fromkeys([*scenario.tags, *plan.emphasis_tags]))

    return scenario.model_copy(update=updates) if updates else scenario


def extract_json_object(text: str) -> str:
    """Best-effort extraction of a JSON object from an LLM text response.

    Handles the common cases of a bare JSON object, one wrapped in a
    markdown ```json fence, or one embedded in surrounding prose despite
    being asked not to. Shared by the `claude` and `ollama` backends.
    """
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    brace = re.search(r"\{.*\}", text, re.DOTALL)
    if brace:
        return brace.group(0)
    return text
