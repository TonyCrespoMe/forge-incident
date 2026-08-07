"""Student + instructor package assembly.

This is the only module that touches the filesystem to write ZIPs.
Everything upstream (`scenario_loader`, `emitters`) works purely with
in-memory `Scenario`/`EmittedArtifact` objects, which keeps this module
the single place where "what goes in which package" is decided.

Two ZIPs are produced from one `Scenario`:

- **Student package**: the emitted logs, unmodified, plus a README built
  entirely from `Scenario.student_briefing` and factual, non-analytic
  metadata (org name, hosts, file listing). Nothing here is generated
  from `Event.description`, `Event.mitre`, `Scenario.description`,
  `Scenario.learning_objectives`, or `Scenario.tags` — every one of
  those fields narrates or hints at the attack chain and is instructor-
  only by design (see models.py and emitters/*.py docstrings).
- **Instructor package**: the same logs, PLUS an instructor guide (full
  narrative timeline with MITRE mapping), the answer key, and a
  machine-readable manifest for grading tooling. Self-contained on
  purpose — an instructor shouldn't need both ZIPs open at once.

Both ZIPs are built byte-for-byte reproducibly for a given `Scenario`
(fixed per-entry timestamps, sorted file order), matching the project's
"full seed-based reproducibility" guarantee all the way through to the
final deliverable. The one intentional exception is the instructor
manifest's `generated_at` field, which records real wall-clock generation
time for provenance; pass an explicit `generated_at` to `build_packages`
if you need two runs' instructor ZIPs to be byte-identical too (e.g. in
a test).
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from forge_incident.emitters import ALL_EMITTERS, EmittedArtifact, Emitter, run_all
from forge_incident.models import Scenario

__all__ = ["PackageResult", "build_packages", "build_manifest"]

# Fixed per-entry timestamp so ZIPs are byte-reproducible across runs.
# zipfile's minimum representable date_time is 1980-01-01.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

_LOG_SOURCE_BLURBS = {
    "gcp_audit": "GCP Cloud Audit Log export (JSON Lines)",
    "aws_cloudtrail": "AWS CloudTrail export (JSON Lines)",
    "azure_activity": "Azure Activity Log / Entra ID audit log export (JSON Lines)",
    "outlook_message_trace": "Exchange Online Message Trace export (CSV)",
    "palo_alto": "Palo Alto Networks (PAN-OS) traffic log export (CSV)",
    "linux": "Linux syslog / auth log export",
    "windows": "Windows Event Log export (XML)",
    "email_eml": "Recovered email message(s) (.eml)",
}


@dataclass(frozen=True)
class PackageResult:
    scenario_id: str
    seed: int
    student_zip: Path
    instructor_zip: Path
    artifact_count: int


def build_packages(
    scenario: Scenario,
    output_dir: str | Path,
    *,
    emitters: tuple[Emitter, ...] = ALL_EMITTERS,
    source_path: str | Path | None = None,
    generated_at: datetime | None = None,
    llm_generated_by: str | None = None,
    generation_warnings: list[str] | None = None,
) -> PackageResult:
    """Render every emitter and write the student + instructor ZIPs.

    `output_dir` is created if needed. Filenames encode the scenario ID
    and seed so re-generating with a different seed never silently
    overwrites a previous run: `<scenario_id>-seed<seed>-student.zip` /
    `...-instructor.zip`.

    `llm_generated_by` (a backend name, e.g. "claude") marks this package
    as coming from `generate-category` rather than a hand-authored/
    template-planned scenario — the instructor guide and manifest get an
    explicit "review before classroom use" notice plus any
    `generation_warnings` from `llm.consistency.check_consistency`. The
    student package is never touched by this — students see identical
    output either way, by design (see `packager.py`'s module docstring).
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = generated_at or datetime.now(timezone.utc)

    artifacts = run_all(scenario, emitters)
    artifacts = sorted(artifacts, key=lambda a: a.relative_path)

    student_files = _student_files(scenario, artifacts)
    instructor_files = _instructor_files(
        scenario,
        artifacts,
        generated_at,
        source_path,
        llm_generated_by=llm_generated_by,
        generation_warnings=generation_warnings or [],
    )

    stem = f"{scenario.scenario_id}-seed{scenario.seed}"
    student_zip = out_dir / f"{stem}-student.zip"
    instructor_zip = out_dir / f"{stem}-instructor.zip"

    _write_zip(student_zip, student_files)
    _write_zip(instructor_zip, instructor_files)

    return PackageResult(
        scenario_id=scenario.scenario_id,
        seed=scenario.seed,
        student_zip=student_zip,
        instructor_zip=instructor_zip,
        artifact_count=len(artifacts),
    )


# --------------------------------------------------------------------------
# Student package contents
# --------------------------------------------------------------------------


def _student_files(scenario: Scenario, artifacts: list[EmittedArtifact]) -> dict[str, str]:
    files = {a.relative_path: a.content for a in artifacts}
    files["README.md"] = _student_readme(scenario, artifacts)
    return files


def _student_readme(scenario: Scenario, artifacts: list[EmittedArtifact]) -> str:
    sources = sorted({_log_source_of(a.relative_path) for a in artifacts})
    lines = [
        f"# {scenario.title}",
        "",
        f"**Organization:** {scenario.organization.name} ({scenario.organization.domain})",
        f"**Difficulty:** {scenario.difficulty.value.capitalize()}",
        "",
        "## Briefing",
        "",
        _as_markdown_paragraphs(scenario.student_briefing),
        "",
        "## Provided evidence",
        "",
    ]
    for source in sources:
        blurb = _LOG_SOURCE_BLURBS.get(source, source)
        files_for_source = sorted(
            a.relative_path for a in artifacts if _log_source_of(a.relative_path) == source
        )
        lines.append(f"- **{blurb}**")
        for f in files_for_source:
            lines.append(f"  - `{f}`")
    lines += [
        "",
        "## Notes",
        "",
        "- All logs in this package cover the same incident window and refer to the "
        "same organization; identifiers (IPs, usernames, hostnames, hashes) are "
        "consistent across every file, so cross-referencing them is the point.",
        "- Work the evidence the way you would a real engagement: form a hypothesis, "
        "look for corroborating or contradicting evidence in another log, and be "
        "ready to justify your conclusions with specific log entries.",
        "- This package was generated by ForgeIncident. It is entirely synthetic "
        "training data — no real individuals, organizations, or systems are "
        "represented.",
        "",
    ]
    return "\n".join(lines)


def _as_markdown_paragraphs(text: str) -> str:
    """Render a YAML folded-scalar string as proper Markdown paragraphs.

    YAML's `>` folded style turns each author blank-line break into a
    single '\\n' in the loaded string (not '\\n\\n') — that single '\\n' is
    the author's intentional paragraph break. Markdown needs a blank line
    to recognize a paragraph break, so we translate one convention to the
    other here rather than asking scenario authors to think about it.
    """
    paragraphs = [p.strip() for p in text.strip().split("\n") if p.strip()]
    return "\n\n".join(paragraphs)


def _log_source_of(relative_path: str) -> str:
    # relative_path is always "logs/<log_source>/...", by construction of
    # every emitter in emitters/*.py.
    parts = relative_path.split("/")
    return parts[1] if len(parts) > 1 else "unknown"


# --------------------------------------------------------------------------
# Instructor package contents
# --------------------------------------------------------------------------


def _instructor_files(
    scenario: Scenario,
    artifacts: list[EmittedArtifact],
    generated_at: datetime,
    source_path: str | Path | None,
    *,
    llm_generated_by: str | None = None,
    generation_warnings: list[str] | None = None,
) -> dict[str, str]:
    generation_warnings = generation_warnings or []
    files = {a.relative_path: a.content for a in artifacts}
    files["README.md"] = _student_readme(scenario, artifacts)
    files["instructor/INSTRUCTOR_GUIDE.md"] = _instructor_guide(
        scenario, artifacts, llm_generated_by=llm_generated_by, generation_warnings=generation_warnings
    )
    files["instructor/ANSWER_KEY.md"] = _answer_key_markdown(scenario)
    files["instructor/manifest.json"] = json.dumps(
        build_manifest(
            scenario,
            artifacts,
            generated_at,
            llm_generated_by=llm_generated_by,
            generation_warnings=generation_warnings,
        ),
        indent=2,
        sort_keys=True,
    )
    if source_path is not None:
        src = Path(source_path)
        if src.is_file():
            files["instructor/scenario_source.yaml"] = src.read_text(encoding="utf-8")
    return files


def _instructor_guide(
    scenario: Scenario,
    artifacts: list[EmittedArtifact],
    *,
    llm_generated_by: str | None = None,
    generation_warnings: list[str] | None = None,
) -> str:
    lines = [f"# Instructor Guide: {scenario.title}", ""]
    if llm_generated_by:
        lines += [
            f"> **⚠ LLM-generated scenario (backend: `{llm_generated_by}`).** This "
            "scenario was written by an LLM from a category brief, then passed "
            "ForgeIncident's structural validation — it was NOT hand-authored or "
            "human-reviewed. Review the full narrative and timeline below before using "
            "it with students, the same way you'd review any new exercise before "
            "assigning it.",
            "",
        ]
        if generation_warnings:
            lines.append("**Automated consistency-check warnings (heuristic, review each one):**")
            lines.append("")
            for w in generation_warnings:
                lines.append(f"- {w}")
            lines.append("")
    lines += [
        f"**Scenario ID:** {scenario.scenario_id}  ",
        f"**Seed:** {scenario.seed}  ",
        f"**Difficulty:** {scenario.difficulty.value}  ",
        f"**MITRE ATT&CK tactics covered:** {', '.join(scenario.mitre_tactics) or 'n/a'}",
        "",
        "## Full narrative",
        "",
        _as_markdown_paragraphs(scenario.description),
        "",
        "## Learning objectives",
        "",
    ]
    lines += [f"- {obj}" for obj in scenario.learning_objectives] or ["- (none listed)"]
    lines += [
        "",
        "## Actors",
        "",
        "| Key | Name | Username | Email | Compromised? |",
        "|---|---|---|---|---|",
    ]
    for key, actor in scenario.actors.items():
        lines.append(
            f"| {key} | {actor.display_name} | {actor.username} | {actor.email} | "
            f"{'yes' if actor.is_compromised else 'no'} |"
        )
    lines += ["", "## Hosts", "", "| Key | Hostname | IP | Type | OS |", "|---|---|---|---|---|"]
    for key, host in scenario.hosts.items():
        lines.append(
            f"| {key} | {host.hostname} | {host.ip_address} | {host.host_type.value} | "
            f"{host.os.value} |"
        )
    lines += [
        "",
        "## Annotated timeline",
        "",
        "Ground truth, in chronological order. Cross-reference `event_id` against "
        "`instructor/manifest.json` to see exactly which rendered log file(s) and "
        "line(s) correspond to each step.",
        "",
        "| # | Timestamp (UTC) | Event ID | Type | MITRE | Actor / Host | Description |",
        "|---|---|---|---|---|---|---|",
    ]
    for event in scenario.timeline:
        mitre = f"{event.mitre.technique_id} {event.mitre.technique_name}" if event.mitre else ""
        actor_host = " / ".join(filter(None, [event.actor, event.host])) or "n/a"
        lines.append(
            f"| {event.index} | {event.timestamp.isoformat()} | `{event.event_id}` | "
            f"{event.event_type.value} | {mitre} | {actor_host} | "
            f"{event.description.strip()} |"
        )
    lines.append("")
    return "\n".join(lines)


def _answer_key_markdown(scenario: Scenario) -> str:
    if not scenario.answer_key:
        return f"# Answer Key: {scenario.title}\n\n(No answer key items defined for this scenario.)\n"

    lines = [f"# Answer Key: {scenario.title}", ""]
    total_points = sum(item.points for item in scenario.answer_key)
    lines.append(f"Total points: {total_points}")
    lines.append("")
    for item in scenario.answer_key:
        lines.append(f"## {item.id}. {item.question} ({item.points} pt{'s' if item.points != 1 else ''})")
        lines.append("")
        lines.append(f"**Answer:** {item.answer.strip()}")
        lines.append("")
        if item.hint:
            lines.append(f"*Hint (if released to students):* {item.hint}")
            lines.append("")
        if item.related_event_ids:
            lines.append(f"*Related timeline events:* {', '.join(item.related_event_ids)}")
            lines.append("")
    return "\n".join(lines)


def build_manifest(
    scenario: Scenario,
    artifacts: list[EmittedArtifact],
    generated_at: datetime,
    *,
    llm_generated_by: str | None = None,
    generation_warnings: list[str] | None = None,
) -> dict:
    """Machine-readable instructor manifest — the same data as the human-readable
    guide, shaped for auto-grading or LMS import tooling."""
    return {
        "forge_incident_version": _package_version(),
        "generated_at": generated_at.astimezone(timezone.utc).isoformat(),
        "scenario_id": scenario.scenario_id,
        "seed": scenario.seed,
        "title": scenario.title,
        "difficulty": scenario.difficulty.value,
        "llm_generated_by": llm_generated_by,
        "generation_warnings": generation_warnings or [],
        "requires_instructor_review": llm_generated_by is not None,
        "mitre_tactics": scenario.mitre_tactics,
        "organization": {
            "name": scenario.organization.name,
            "domain": scenario.organization.domain,
        },
        "artifacts": [
            {"path": a.relative_path, "description": a.description} for a in artifacts
        ],
        "timeline": [
            {
                "event_id": e.event_id,
                "index": e.index,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type.value,
                "severity": e.severity.value,
                "log_sources": [s.value for s in e.log_sources],
                "actor": e.actor,
                "host": e.host,
                "mitre": (
                    {
                        "technique_id": e.mitre.technique_id,
                        "technique_name": e.mitre.technique_name,
                        "tactic": e.mitre.tactic,
                    }
                    if e.mitre
                    else None
                ),
                "description": e.description,
            }
            for e in scenario.timeline
        ],
        "answer_key": [
            {
                "id": item.id,
                "question": item.question,
                "answer": item.answer,
                "points": item.points,
                "related_event_ids": item.related_event_ids,
            }
            for item in scenario.answer_key
        ],
    }


def _package_version() -> str:
    try:
        from forge_incident import __version__

        return __version__
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------
# ZIP writing
# --------------------------------------------------------------------------


def _write_zip(zip_path: Path, files: dict[str, str]) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for relative_path in sorted(files):
            info = zipfile.ZipInfo(relative_path, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, files[relative_path])
    zip_path.write_bytes(buffer.getvalue())
