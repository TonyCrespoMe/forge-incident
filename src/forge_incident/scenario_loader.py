"""Load YAML scenario files into validated `models.Scenario` objects.

Design goals:

1. **Authors write relative time, not absolute time.** Every timeline entry
   has an `at` offset (e.g. `"+6m"`, `"+1h30m"`) measured from the
   scenario's `start_time`. This keeps YAML scenarios easy to read/edit
   and easy to shift to "today" without touching every line.

2. **Full seed-based reproducibility.** The only randomness this module
   introduces is small, deterministic timestamp jitter (so events don't
   land on suspiciously round seconds) driven by a `random.Random` seeded
   from the scenario's seed. Same file + same seed => byte-identical
   `Scenario` output, always. `derive_rng()` is exposed so emitters can
   get their own reproducible, independent random streams later (e.g. for
   inventing decoy log noise) without needing to share loader internals.

3. **Fail loudly, fail clearly.** Both YAML syntax errors and Pydantic
   validation errors are re-raised as `ScenarioLoadError` with a message
   that points at the offending file and field, since scenario authors
   are the primary audience for these errors.

Nothing in this module talks to an LLM. Natural-language scenario
generation (see `llm/`) produces the same YAML-shaped structure that this
loader consumes, so there is exactly one code path that turns "a scenario
description" into a validated `Scenario`.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from forge_incident.models import (
    AnswerKeyItem,
    Difficulty,
    Event,
    Host,
    Identity,
    OrgProfile,
    Scenario,
)

__all__ = [
    "ScenarioLoadError",
    "ScenarioSummary",
    "load_scenario",
    "list_scenarios",
    "derive_rng",
]

_OFFSET_RE = re.compile(
    r"^(?P<sign>[+-])"
    r"(?:(?P<days>\d+)d)?"
    r"(?:(?P<hours>\d+)h)?"
    r"(?:(?P<minutes>\d+)m)?"
    r"(?:(?P<seconds>\d+)s)?$"
)

_DEFAULT_JITTER_SECONDS = 3


class ScenarioLoadError(Exception):
    """Raised for any problem loading/validating a scenario file.

    Wraps both YAML syntax errors and Pydantic validation errors so
    callers (the CLI) only need to catch one exception type and print
    `str(exc)` to get an actionable, file-scoped message.
    """


# --------------------------------------------------------------------------
# Determinism helpers
# --------------------------------------------------------------------------


def derive_rng(seed: int, *parts: str) -> random.Random:
    """Return an independent, reproducible `random.Random` stream.

    Every caller that mixes in a different `parts` tuple gets a stream
    that is statistically independent of every other caller's stream, but
    every stream is fully determined by `seed`. This lets, e.g., the
    Linux emitter and the Windows emitter both invent "background noise"
    events from the same scenario seed without their random choices
    silently correlating (or colliding) with each other.

    Example: `derive_rng(scenario.seed, "linux", "auth_noise")`
    """
    digest = hashlib.sha256(f"{seed}:{'|'.join(parts)}".encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def _parse_offset(at: str) -> timedelta:
    match = _OFFSET_RE.match(at.strip())
    if not match:
        raise ScenarioLoadError(
            f"Invalid 'at' offset {at!r}. Expected a relative offset like '+0m', "
            "'+5m30s', '+1h', or '-10s' (units: d, h, m, s, combinable)."
        )
    groups = match.groupdict()
    if not any(groups[k] for k in ("days", "hours", "minutes", "seconds")):
        raise ScenarioLoadError(f"'at' offset {at!r} has a sign but no duration components.")
    delta = timedelta(
        days=int(groups["days"] or 0),
        hours=int(groups["hours"] or 0),
        minutes=int(groups["minutes"] or 0),
        seconds=int(groups["seconds"] or 0),
    )
    return -delta if groups["sign"] == "-" else delta


def _parse_at(at: Any, start_time: datetime) -> datetime:
    """Resolve a timeline entry's `at` field to an absolute UTC timestamp.

    Accepts either a relative offset ('+6m') or a full ISO-8601 absolute
    timestamp, so authors can pin a specific event in time if they need
    to (e.g. to line up with a real calendar date in a training cohort).
    """
    if not isinstance(at, str):
        raise ScenarioLoadError(f"Timeline entry 'at' must be a string, got {type(at).__name__}")
    text = at.strip()
    if text and text[0] in "+-":
        return start_time + _parse_offset(text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScenarioLoadError(
            f"Could not parse 'at' value {at!r} as a relative offset (+6m) "
            "or an ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_start_time(raw: Any, scenario_id: str) -> datetime:
    if not isinstance(raw, str):
        raise ScenarioLoadError(f"[{scenario_id}] 'start_time' must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScenarioLoadError(
            f"[{scenario_id}] 'start_time' {raw!r} is not a valid ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _require(raw: dict[str, Any], key: str, scenario_id: str = "<unknown>") -> Any:
    if key not in raw:
        raise ScenarioLoadError(f"[{scenario_id}] missing required top-level key: {key!r}")
    return raw[key]


# --------------------------------------------------------------------------
# Core loader
# --------------------------------------------------------------------------


def load_scenario(path: str | Path, seed: int | None = None) -> Scenario:
    """Load and validate a YAML scenario file.

    Args:
        path: Path to a `.yaml`/`.yml` scenario file.
        seed: If given, overrides the `seed` declared in the YAML file.
            This is what the CLI's `--seed` flag maps to: same scenario
            file, different seed, deterministic-but-different jitter and
            downstream emitter randomness.

    Returns:
        A fully validated `Scenario`. Raises `ScenarioLoadError` on any
        YAML syntax error, missing/malformed field, or cross-reference
        problem (e.g. an event pointing at an actor that doesn't exist).
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ScenarioLoadError(f"Scenario file not found: {file_path}")

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioLoadError(f"YAML syntax error in {file_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScenarioLoadError(f"{file_path}: top-level YAML document must be a mapping")

    scenario_id = raw.get("scenario_id", file_path.stem)

    try:
        return _build_scenario(raw, scenario_id=scenario_id, seed_override=seed)
    except ScenarioLoadError:
        raise
    except ValidationError as exc:
        raise ScenarioLoadError(
            f"[{scenario_id}] failed validation ({file_path}):\n{_format_pydantic_error(exc)}"
        ) from exc


def _format_pydantic_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = " -> ".join(str(p) for p in err["loc"])
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)


def _build_scenario(raw: dict[str, Any], *, scenario_id: str, seed_override: int | None) -> Scenario:
    effective_seed = seed_override if seed_override is not None else raw.get("seed")
    if effective_seed is None:
        raise ScenarioLoadError(
            f"[{scenario_id}] no seed available: set 'seed' in the YAML file or pass "
            "--seed on the CLI."
        )

    org_raw = _require(raw, "organization", scenario_id)
    organization = OrgProfile.model_validate(org_raw)

    actors_raw = _require(raw, "actors", scenario_id)
    if not isinstance(actors_raw, dict) or not actors_raw:
        raise ScenarioLoadError(f"[{scenario_id}] 'actors' must be a non-empty mapping")
    actors = {key: Identity.model_validate(val) for key, val in actors_raw.items()}

    hosts_raw = raw.get("hosts", {}) or {}
    hosts = {key: Host.model_validate(val) for key, val in hosts_raw.items()}

    start_time = _parse_start_time(_require(raw, "start_time", scenario_id), scenario_id)

    timeline_raw = _require(raw, "timeline", scenario_id)
    if not isinstance(timeline_raw, list) or not timeline_raw:
        raise ScenarioLoadError(f"[{scenario_id}] 'timeline' must be a non-empty list")

    jitter_seconds = int(raw.get("timestamp_jitter_seconds", _DEFAULT_JITTER_SECONDS))
    jitter_rng = derive_rng(effective_seed, "scenario_loader", "timestamp_jitter")

    timeline: list[Event] = []
    previous_ts: datetime | None = None
    for index, entry in enumerate(timeline_raw):
        if not isinstance(entry, dict):
            raise ScenarioLoadError(
                f"[{scenario_id}] timeline[{index}] must be a mapping, got {type(entry).__name__}"
            )
        entry = dict(entry)  # avoid mutating caller's parsed YAML

        at = entry.pop("at", None)
        if at is None:
            raise ScenarioLoadError(f"[{scenario_id}] timeline[{index}] missing required key 'at'")
        base_ts = _parse_at(at, start_time)

        ts = _apply_jitter(base_ts, previous_ts, jitter_seconds, jitter_rng)
        previous_ts = ts

        event_id = entry.pop("id", None) or f"{scenario_id}::{index:04d}"

        try:
            event = Event.model_validate(
                {
                    **entry,
                    "event_id": event_id,
                    "index": index,
                    "timestamp": ts,
                }
            )
        except ValidationError as exc:
            raise ScenarioLoadError(
                f"[{scenario_id}] timeline[{index}] (id={event_id}) failed validation:\n"
                f"{_format_pydantic_error(exc)}"
            ) from exc
        timeline.append(event)

    answer_key_raw = raw.get("answer_key", []) or []
    answer_key = [AnswerKeyItem.model_validate(item) for item in answer_key_raw]

    difficulty_raw = raw.get("difficulty", Difficulty.INTERMEDIATE.value)

    try:
        return Scenario(
            scenario_id=scenario_id,
            title=_require(raw, "title", scenario_id),
            description=_require(raw, "description", scenario_id),
            student_briefing=_require(raw, "student_briefing", scenario_id),
            difficulty=difficulty_raw,
            version=str(raw.get("version", "1.0")),
            seed=int(effective_seed),
            organization=organization,
            mitre_tactics=list(raw.get("mitre_tactics", []) or []),
            learning_objectives=list(raw.get("learning_objectives", []) or []),
            tags=list(raw.get("tags", []) or []),
            actors=actors,
            hosts=hosts,
            timeline=timeline,
            answer_key=answer_key,
        )
    except ValidationError as exc:
        raise ScenarioLoadError(
            f"[{scenario_id}] failed cross-field validation:\n{_format_pydantic_error(exc)}"
        ) from exc


def _apply_jitter(
    base_ts: datetime,
    previous_ts: datetime | None,
    jitter_seconds: int,
    rng: random.Random,
) -> datetime:
    """Nudge a timestamp by up to +/- jitter_seconds, deterministically.

    Real logs are never on exact round seconds; jitter makes generated
    timelines look organic. To guarantee `Scenario.timeline` stays sorted
    (a hard invariant in `models.Scenario`), if jitter would place this
    event at or before the previous (already-jittered) event, it is
    clamped to one second after it instead. Order and narrative pacing
    always come from the YAML's `at` offsets; jitter never reorders
    events.
    """
    if jitter_seconds > 0:
        offset = rng.randint(-jitter_seconds, jitter_seconds)
        candidate = base_ts + timedelta(seconds=offset)
    else:
        candidate = base_ts
    if previous_ts is not None and candidate <= previous_ts:
        candidate = previous_ts + timedelta(seconds=1)
    return candidate


# --------------------------------------------------------------------------
# Listing scenarios (for `forge-incident list`)
# --------------------------------------------------------------------------


@dataclass
class ScenarioSummary:
    """Lightweight, listing-friendly view of a scenario file.

    Produced by `list_scenarios()` for the CLI's `list` command. Kept
    separate from `models.Scenario` because listing must stay fast and
    resilient even if a particular scenario file fails full validation
    (`is_valid=False` + `error` set, rather than raising).
    """

    path: Path
    scenario_id: str
    title: str
    description: str
    difficulty: str
    tags: list[str] = field(default_factory=list)
    event_count: int | None = None
    is_valid: bool = True
    error: str | None = None


def list_scenarios(directory: str | Path) -> list[ScenarioSummary]:
    """Discover and (best-effort) validate every scenario in a directory.

    Each `*.yaml`/`*.yml` file is fully loaded via `load_scenario` so the
    reported `event_count` is trustworthy; a file that fails to load is
    still listed (so `forge-incident list` shows the whole directory) but
    flagged `is_valid=False` with the error message instead of raising.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise ScenarioLoadError(f"Scenario directory not found: {dir_path}")

    summaries: list[ScenarioSummary] = []
    for file_path in sorted(dir_path.glob("*.yml")) + sorted(dir_path.glob("*.yaml")):
        try:
            scenario = load_scenario(file_path)
        except ScenarioLoadError as exc:
            summaries.append(
                ScenarioSummary(
                    path=file_path,
                    scenario_id=file_path.stem,
                    title=file_path.stem,
                    description="",
                    difficulty="unknown",
                    is_valid=False,
                    error=str(exc),
                )
            )
            continue
        summaries.append(
            ScenarioSummary(
                path=file_path,
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                description=scenario.description,
                difficulty=scenario.difficulty.value,
                tags=scenario.tags,
                event_count=scenario.event_count,
                is_valid=True,
            )
        )
    return summaries
