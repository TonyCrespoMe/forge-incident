"""Round-tripping a scenario between YAML, editable tables, and back.

Kept separate from `app.py` (which is all Streamlit widgets) so this logic
is importable and unit-testable WITHOUT Streamlit installed — the offline
test suite exercises it directly. That split matters: the risky part of a
timeline editor isn't the widgets, it's "does an edit survive the trip
back to valid YAML", and that part is now testable.

Design rule: the editor never writes a scenario file that hasn't been
re-validated by `scenario_loader`. The UI edits a plain dict, this module
serializes it to YAML, and the caller runs it back through
`load_scenario_from_text` before anything is saved or generated from. So
the browser path has exactly the same validation guarantees as the CLI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

import yaml

from forge_incident.models import Scenario

__all__ = [
    "TIMELINE_COLUMNS",
    "scenario_to_raw",
    "timeline_to_rows",
    "rows_to_timeline",
    "raw_to_yaml",
    "offset_from_start",
    "dangling_answer_key_refs",
    "prune_dangling_answer_key_refs",
]

#: The subset of event fields the tabular editor exposes. Payload blocks
#: (process/email/network/cloud/file) are edited as YAML in a side panel
#: rather than flattened into columns — flattening them would produce a
#: 40-column table that's harder to use than the YAML it replaced.
TIMELINE_COLUMNS = [
    "id",
    "at",
    "event_type",
    "log_sources",
    "severity",
    "actor",
    "host",
    "description",
]


def _plain(value: Any) -> Any:
    """Coerce a model value into something PyYAML can represent.

    Necessary because a payload's `model_dump()` can hand back values that
    are *subclasses* of primitives (notably `EmailStr`, a `str` subclass)
    or `Enum` members — and `yaml.safe_dump` refuses both, raising
    `RepresenterError` rather than silently writing something wrong. Doing
    this once here keeps every caller from having to think about it.
    """
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def offset_from_start(timestamp: datetime, start_time: datetime) -> str:
    """Render an absolute timestamp back as a scenario `at:` offset.

    `scenario_loader` applies seeded jitter when loading, so a round-trip
    through absolute timestamps would bake that jitter into the file and
    re-jitter it on the next load. Rounding to the nearest minute here
    keeps offsets stable and human-readable across edit cycles; sub-minute
    pacing should be expressed in the YAML directly.
    """
    delta = timestamp - start_time
    total_seconds = int(delta.total_seconds())
    sign = "-" if total_seconds < 0 else "+"
    total_seconds = abs(total_seconds)

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    # Drop stray seconds introduced by jitter; keep them only if the whole
    # offset is sub-minute (where they're clearly intentional).
    if days or hours or minutes:
        seconds = 0

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return sign + "".join(parts)


def scenario_to_raw(scenario: Scenario, start_time: datetime | None = None) -> dict[str, Any]:
    """A validated `Scenario` back into the YAML-shaped dict authors write.

    This is the inverse of `scenario_loader._build_scenario`, so what the
    editor shows is the same structure a hand-written scenario file has —
    not an internal representation the user has never seen.
    """
    start = start_time or scenario.start_time

    raw: dict[str, Any] = {
        "scenario_id": _plain(scenario.scenario_id),
        "title": _plain(scenario.title),
        "description": _plain(scenario.description),
        "student_briefing": _plain(scenario.student_briefing),
        "difficulty": scenario.difficulty.value,
        "version": _plain(scenario.version),
        "seed": int(scenario.seed),
        "organization": {
            k: _plain(v)
            for k, v in {
                "name": scenario.organization.name,
                "domain": scenario.organization.domain,
                "industry": scenario.organization.industry,
                "timezone": scenario.organization.timezone,
                "gcp_project_id": scenario.organization.gcp_project_id,
            }.items()
            if v is not None
        },
        "mitre_tactics": [_plain(t) for t in scenario.mitre_tactics],
        "learning_objectives": [_plain(o) for o in scenario.learning_objectives],
        "tags": [_plain(t) for t in scenario.tags],
        "start_time": start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actors": {},
        "hosts": {},
        "timeline": [],
        "answer_key": [],
    }

    for key, actor in scenario.actors.items():
        raw["actors"][key] = {
            k: _plain(v)
            for k, v in {
                "username": actor.username,
                "email": str(actor.email),
                "display_name": actor.display_name,
                "department": actor.department,
                "role_title": actor.role_title,
                "employee_id": actor.employee_id,
                "is_compromised": actor.is_compromised or None,
                "is_privileged": actor.is_privileged or None,
            }.items()
            if v is not None
        }

    for key, host in scenario.hosts.items():
        raw["hosts"][key] = {
            k: _plain(v)
            for k, v in {
                "hostname": host.hostname,
                "ip_address": host.ip_address,
                "host_type": host.host_type.value,
                "os": host.os.value,
                "os_version": host.os_version,
                "mac_address": host.mac_address,
                "domain_joined": None if host.domain_joined else False,
            }.items()
            if v is not None
        }

    for event in scenario.timeline:
        entry: dict[str, Any] = {
            "id": event.event_id,
            "at": offset_from_start(event.timestamp, start),
            "event_type": event.event_type.value,
            "log_sources": [s.value for s in event.log_sources],
            "severity": event.severity.value,
        }
        if event.actor:
            entry["actor"] = event.actor
        if event.host:
            entry["host"] = event.host
        entry["description"] = event.description
        if event.mitre:
            entry["mitre"] = {
                "technique_id": event.mitre.technique_id,
                "technique_name": event.mitre.technique_name,
                "tactic": event.mitre.tactic,
            }
        for payload_name in ("process", "email", "network", "cloud", "file"):
            payload = getattr(event, payload_name, None)
            if payload is not None:
                entry[payload_name] = {
                    k: _plain(v) for k, v in payload.model_dump().items() if v is not None
                }
        if event.tags:
            entry["tags"] = [_plain(t) for t in event.tags]
        if event.extra:
            entry["extra"] = _plain(dict(event.extra))
        raw["timeline"].append(entry)

    for item in scenario.answer_key:
        entry = {
            "id": _plain(item.id),
            "question": _plain(item.question),
            "answer": _plain(item.answer),
            "points": _plain(item.points),
        }
        if item.related_event_ids:
            entry["related_event_ids"] = [_plain(i) for i in item.related_event_ids]
        if item.hint:
            entry["hint"] = _plain(item.hint)
        raw["answer_key"].append(entry)

    return raw


def timeline_to_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Timeline entries as flat rows for a data-editor grid.

    Payload blocks are intentionally NOT flattened — `rows_to_timeline`
    merges edited rows back over the original entries, preserving whatever
    payloads each event had.
    """
    rows = []
    for entry in raw.get("timeline", []):
        row = {column: entry.get(column, "") for column in TIMELINE_COLUMNS}
        row["log_sources"] = ", ".join(entry.get("log_sources", []) or [])
        row["description"] = (entry.get("description") or "").strip()
        rows.append(row)
    return rows


def rows_to_timeline(
    rows: list[dict[str, Any]], original_timeline: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge edited grid rows back over the original timeline entries.

    Matching is by `id`, so reordering rows in the grid reorders the
    timeline, editing a cell updates just that field, and a brand-new row
    (an id not present in the original) becomes a new event with only the
    tabular fields set — the author then adds payloads in the YAML panel.
    Deleting a row deletes the event.
    """
    by_id = {entry.get("id"): entry for entry in original_timeline}
    merged: list[dict[str, Any]] = []

    for row in rows:
        event_id = (row.get("id") or "").strip()
        if not event_id:
            continue  # skip blank rows the grid adds by default
        entry = dict(by_id.get(event_id, {}))
        entry["id"] = event_id

        for column in TIMELINE_COLUMNS:
            if column == "id":
                continue
            value = row.get(column)
            if column == "log_sources":
                sources = [s.strip() for s in str(value or "").split(",") if s.strip()]
                if sources:
                    entry["log_sources"] = sources
                continue
            if value in (None, ""):
                # Only clear optional fields; never blank out required ones.
                if column in ("actor", "host"):
                    entry.pop(column, None)
                continue
            entry[column] = value

        merged.append(entry)

    return merged


def dangling_answer_key_refs(raw: dict[str, Any]) -> dict[str, list[str]]:
    """Answer-key items pointing at timeline events that no longer exist.

    Deleting a timeline row in the editor is the easy way to break a
    scenario: `models.Scenario` hard-rejects an `answer_key` item that
    references a missing `event_id`, so the save would fail with a
    validation error *after* the user has already done the work. The UI
    calls this first so it can warn (and offer to fix) up front instead.

    Returns `{answer_key_id: [missing_event_id, ...]}` — empty if fine.
    """
    known = {entry.get("id") for entry in raw.get("timeline", [])}
    dangling: dict[str, list[str]] = {}
    for item in raw.get("answer_key", []) or []:
        missing = [ref for ref in (item.get("related_event_ids") or []) if ref not in known]
        if missing:
            dangling[str(item.get("id", "?"))] = missing
    return dangling


def prune_dangling_answer_key_refs(raw: dict[str, Any]) -> dict[str, Any]:
    """Drop answer-key references to deleted events, returning a new dict.

    The answer-key *items* are kept (their question and prose answer are
    still valid instructor content) — only the now-broken event pointers
    are removed. Callers should surface what changed rather than doing
    this silently; the UI shows an explicit warning listing each one.
    """
    known = {entry.get("id") for entry in raw.get("timeline", [])}
    cleaned = dict(raw)
    cleaned["answer_key"] = []
    for item in raw.get("answer_key", []) or []:
        new_item = dict(item)
        refs = [ref for ref in (item.get("related_event_ids") or []) if ref in known]
        if refs:
            new_item["related_event_ids"] = refs
        else:
            new_item.pop("related_event_ids", None)
        cleaned["answer_key"].append(new_item)
    return cleaned


def raw_to_yaml(raw: dict[str, Any]) -> str:
    """Serialize an edited scenario dict back to YAML text.

    `sort_keys=False` preserves the human-meaningful ordering built in
    `scenario_to_raw` (identity → narrative → cast → timeline) rather than
    alphabetizing it into something no scenario author would write.
    """
    return yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=100)
