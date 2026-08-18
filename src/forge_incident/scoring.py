"""Scoring a student's investigation against a scenario's ground truth.

A ForgeIncident scenario already contains everything needed to grade an
exercise objectively: the timeline is the ground truth of what actually
happened, each `Event` carries a severity and (usually) an ATT&CK mapping,
and the answer key ties questions back to specific events. This module
turns that into three metrics instructors actually care about:

- **Detection coverage** — of the events that a competent analyst *should*
  have flagged, how many did the student find? Reported overall and broken
  down per ATT&CK tactic, so "they caught the malware but missed the whole
  exfiltration phase" is visible rather than averaged away.
- **False positives** — how many things did they flag that weren't
  actually malicious? Tracked separately from misses, because an analyst
  who flags everything would otherwise score 100% coverage.
- **Response time** — how long after each event occurred did the student
  detect it, plus time-to-first-detection measured from the first
  malicious event. This is the metric that separates "found it eventually"
  from "would have caught it before exfiltration."

What counts as a detection opportunity
--------------------------------------
By default: every event that carries a MITRE technique **or** has severity
`medium` or above. Everything else (a user's normal login, a legitimate
file save) is a *benign* event, and flagging one is a false positive.
Scenario authors don't have to annotate anything extra for this to work —
it falls out of the `mitre`/`severity` fields scenarios already set. Pass a
custom `is_opportunity` predicate to `score_submission` if a particular
course wants a different bar.

Nothing here is LLM-driven or fuzzy: scoring is deterministic and depends
only on the scenario + the submission, so two instructors grading the same
submission always get identical numbers.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from forge_incident.models import Event, Scenario, Severity

__all__ = [
    "Detection",
    "Submission",
    "DetectionOutcome",
    "ScoreReport",
    "default_is_opportunity",
    "load_submission",
    "score_submission",
    "submission_template",
    "render_report_markdown",
]

_OPPORTUNITY_SEVERITIES = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def default_is_opportunity(event: Event) -> bool:
    """Should a competent analyst have flagged this event?

    True if it carries an ATT&CK technique (i.e. the scenario author
    considered it an adversary action) or its severity is medium+.
    """
    return event.mitre is not None or event.severity in _OPPORTUNITY_SEVERITIES


class SubmissionError(Exception):
    """Raised when a submission file is missing, malformed, or unparseable."""


@dataclass(frozen=True)
class Detection:
    """One thing a student claims they detected."""

    event_id: str
    detected_at: datetime | None = None
    notes: str = ""


@dataclass
class Submission:
    """A student's completed investigation, ready to be scored."""

    analyst: str = "unknown"
    scenario_id: str = ""
    detections: list[Detection] = field(default_factory=list)
    #: Optional free-text answers keyed by answer_key item id ("q1", ...).
    #: Not auto-graded — surfaced in the report for manual marking, since
    #: grading prose correctly is a human job.
    answers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionOutcome:
    """The result of matching one claimed detection against ground truth."""

    event_id: str
    #: "true_positive" | "false_positive_benign" | "false_positive_unknown"
    verdict: str
    event_timestamp: datetime | None = None
    detected_at: datetime | None = None
    #: Seconds between the event happening and the student detecting it.
    latency_seconds: float | None = None
    tactic: str = ""


@dataclass
class ScoreReport:
    scenario_id: str
    analyst: str
    total_opportunities: int
    detected_count: int
    missed_event_ids: list[str]
    outcomes: list[DetectionOutcome]
    coverage_by_tactic: dict[str, tuple[int, int]]  # tactic -> (detected, total)
    false_positive_count: int
    unknown_event_id_count: int
    latencies: list[float]
    time_to_first_detection_seconds: float | None
    answers: dict[str, str] = field(default_factory=dict)

    @property
    def coverage_pct(self) -> float:
        if self.total_opportunities == 0:
            return 0.0
        return 100.0 * self.detected_count / self.total_opportunities

    @property
    def precision_pct(self) -> float:
        """Of everything the student flagged, how much was actually malicious?"""
        claimed = self.detected_count + self.false_positive_count + self.unknown_event_id_count
        if claimed == 0:
            return 0.0
        return 100.0 * self.detected_count / claimed

    @property
    def mean_latency_seconds(self) -> float | None:
        return statistics.mean(self.latencies) if self.latencies else None

    @property
    def median_latency_seconds(self) -> float | None:
        return statistics.median(self.latencies) if self.latencies else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "analyst": self.analyst,
            "detection_coverage": {
                "detected": self.detected_count,
                "total_opportunities": self.total_opportunities,
                "coverage_pct": round(self.coverage_pct, 1),
                "missed_event_ids": self.missed_event_ids,
                "by_tactic": {
                    tactic: {
                        "detected": found,
                        "total": total,
                        "coverage_pct": round(100.0 * found / total, 1) if total else 0.0,
                    }
                    for tactic, (found, total) in sorted(self.coverage_by_tactic.items())
                },
            },
            "false_positives": {
                "benign_events_flagged": self.false_positive_count,
                "unknown_event_ids": self.unknown_event_id_count,
                "precision_pct": round(self.precision_pct, 1),
            },
            "response_time": {
                "time_to_first_detection_seconds": self.time_to_first_detection_seconds,
                "mean_latency_seconds": self.mean_latency_seconds,
                "median_latency_seconds": self.median_latency_seconds,
                "per_detection": [
                    {
                        "event_id": o.event_id,
                        "latency_seconds": o.latency_seconds,
                    }
                    for o in self.outcomes
                    if o.verdict == "true_positive" and o.latency_seconds is not None
                ],
            },
            "outcomes": [
                {
                    "event_id": o.event_id,
                    "verdict": o.verdict,
                    "tactic": o.tactic,
                    "latency_seconds": o.latency_seconds,
                }
                for o in self.outcomes
            ],
            "answers_for_manual_review": self.answers,
        }


# --------------------------------------------------------------------------
# Loading a submission
# --------------------------------------------------------------------------


def _parse_timestamp(raw: Any, context: str) -> datetime | None:
    if raw in (None, ""):
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        raise SubmissionError(f"{context}: 'detected_at' must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SubmissionError(
            f"{context}: 'detected_at' value {raw!r} is not a valid ISO-8601 timestamp "
            "(e.g. '2026-03-10T09:15:00Z')"
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def load_submission(path: str | Path) -> Submission:
    """Load a student submission from JSON (or YAML, if it ends in .yaml/.yml)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise SubmissionError(f"Submission file not found: {file_path}")

    text = file_path.read_text(encoding="utf-8")
    try:
        if file_path.suffix.lower() in (".yaml", ".yml"):
            import yaml

            raw = yaml.safe_load(text)
        else:
            raw = json.loads(text)
    except Exception as exc:
        raise SubmissionError(f"Could not parse {file_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise SubmissionError(f"{file_path}: top-level document must be an object/mapping")

    detections_raw = raw.get("detections") or []
    if not isinstance(detections_raw, list):
        raise SubmissionError(f"{file_path}: 'detections' must be a list")

    detections: list[Detection] = []
    for index, item in enumerate(detections_raw):
        context = f"{file_path} detections[{index}]"
        if isinstance(item, str):
            detections.append(Detection(event_id=item))
            continue
        if not isinstance(item, dict):
            raise SubmissionError(f"{context}: must be an object or a plain event_id string")
        event_id = item.get("event_id")
        if not event_id:
            raise SubmissionError(f"{context}: missing required 'event_id'")
        detections.append(
            Detection(
                event_id=str(event_id),
                detected_at=_parse_timestamp(item.get("detected_at"), context),
                notes=str(item.get("notes", "")),
            )
        )

    return Submission(
        analyst=str(raw.get("analyst", "unknown")),
        scenario_id=str(raw.get("scenario_id", "")),
        detections=detections,
        answers={str(k): str(v) for k, v in (raw.get("answers") or {}).items()},
    )


def submission_template(scenario: Scenario) -> str:
    """A ready-to-fill submission file for a student, as pretty JSON.

    Deliberately contains NO spoilers: it names the scenario and the
    answer-key question ids, but never which events are malicious — that's
    the whole exercise.
    """
    template = {
        "analyst": "your name",
        "scenario_id": scenario.scenario_id,
        "_instructions": (
            "For each suspicious event you identify, add an entry to 'detections'. "
            "'event_id' should reference the event as labelled in the evidence you were "
            "given (or a short slug you and your instructor agree on). 'detected_at' is "
            "when YOU spotted it (ISO-8601, e.g. '2026-03-10T09:15:00Z') and is used to "
            "measure response time -- leave it out if your course isn't timing you."
        ),
        "detections": [
            {"event_id": "<event id>", "detected_at": None, "notes": "why this is suspicious"}
        ],
        "answers": {item.id: "" for item in scenario.answer_key},
    }
    return json.dumps(template, indent=2) + "\n"


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def score_submission(
    scenario: Scenario,
    submission: Submission,
    *,
    is_opportunity: Callable[[Event], bool] = default_is_opportunity,
) -> ScoreReport:
    """Grade a submission against a scenario's ground truth.

    Deterministic: same scenario (same seed) + same submission always
    produces the same numbers.
    """
    events_by_id = {event.event_id: event for event in scenario.timeline}
    opportunities = {
        event.event_id: event for event in scenario.timeline if is_opportunity(event)
    }

    # Per-tactic totals come from the ground truth, not the submission, so a
    # tactic the student entirely missed still shows up as 0/N rather than
    # vanishing from the report.
    coverage_by_tactic: dict[str, tuple[int, int]] = {}
    for event in opportunities.values():
        tactic = event.mitre.tactic if event.mitre else "Unmapped"
        found, total = coverage_by_tactic.get(tactic, (0, 0))
        coverage_by_tactic[tactic] = (found, total + 1)

    outcomes: list[DetectionOutcome] = []
    latencies: list[float] = []
    detected_ids: set[str] = set()
    false_positives = 0
    unknown_ids = 0

    for detection in submission.detections:
        event = events_by_id.get(detection.event_id)
        if event is None:
            unknown_ids += 1
            outcomes.append(
                DetectionOutcome(event_id=detection.event_id, verdict="false_positive_unknown")
            )
            continue

        tactic = event.mitre.tactic if event.mitre else "Unmapped"

        if detection.event_id not in opportunities:
            false_positives += 1
            outcomes.append(
                DetectionOutcome(
                    event_id=detection.event_id,
                    verdict="false_positive_benign",
                    event_timestamp=event.timestamp,
                    detected_at=detection.detected_at,
                    tactic=tactic,
                )
            )
            continue

        # A true positive. Duplicate claims for the same event count once
        # toward coverage (flagging the same thing twice isn't extra credit).
        latency = None
        if detection.detected_at is not None:
            latency = (detection.detected_at - event.timestamp).total_seconds()
            if detection.event_id not in detected_ids:
                latencies.append(latency)

        if detection.event_id not in detected_ids:
            found, total = coverage_by_tactic[tactic]
            coverage_by_tactic[tactic] = (found + 1, total)
        detected_ids.add(detection.event_id)

        outcomes.append(
            DetectionOutcome(
                event_id=detection.event_id,
                verdict="true_positive",
                event_timestamp=event.timestamp,
                detected_at=detection.detected_at,
                latency_seconds=latency,
                tactic=tactic,
            )
        )

    # Time-to-first-detection: from the FIRST malicious event in the
    # scenario to the student's earliest correct detection. This is the
    # "how long was the adversary operating unnoticed" number.
    time_to_first: float | None = None
    detection_times = [
        o.detected_at for o in outcomes if o.verdict == "true_positive" and o.detected_at
    ]
    if detection_times and opportunities:
        first_malicious = min(e.timestamp for e in opportunities.values())
        time_to_first = (min(detection_times) - first_malicious).total_seconds()

    missed = sorted(set(opportunities) - detected_ids)

    return ScoreReport(
        scenario_id=scenario.scenario_id,
        analyst=submission.analyst,
        total_opportunities=len(opportunities),
        detected_count=len(detected_ids),
        missed_event_ids=missed,
        outcomes=outcomes,
        coverage_by_tactic=coverage_by_tactic,
        false_positive_count=false_positives,
        unknown_event_id_count=unknown_ids,
        latencies=latencies,
        time_to_first_detection_seconds=time_to_first,
        answers=submission.answers,
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{sign}{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{sign}{minutes}m {secs}s"
    return f"{sign}{secs}s"


def render_report_markdown(report: ScoreReport, scenario: Scenario) -> str:
    """Instructor-facing scored report. Contains full spoilers by design."""
    lines = [
        f"# Score Report: {scenario.title}",
        "",
        f"**Analyst:** {report.analyst}  ",
        f"**Scenario:** `{report.scenario_id}` (seed {scenario.seed}, "
        f"difficulty {scenario.difficulty.value})",
        "",
        "## Summary",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Detection coverage | **{report.coverage_pct:.0f}%** "
        f"({report.detected_count}/{report.total_opportunities} opportunities) |",
        f"| Precision | **{report.precision_pct:.0f}%** "
        f"({report.false_positive_count + report.unknown_event_id_count} false positive(s)) |",
        f"| Time to first detection | **{_format_duration(report.time_to_first_detection_seconds)}** |",
        f"| Mean detection latency | {_format_duration(report.mean_latency_seconds)} |",
        f"| Median detection latency | {_format_duration(report.median_latency_seconds)} |",
        "",
        "## Detection coverage by ATT&CK tactic",
        "",
        "| Tactic | Detected | Total | Coverage |",
        "|---|---:|---:|---:|",
    ]
    for tactic, (found, total) in sorted(report.coverage_by_tactic.items()):
        pct = 100.0 * found / total if total else 0.0
        lines.append(f"| {tactic} | {found} | {total} | {pct:.0f}% |")

    lines += ["", "## Missed detection opportunities", ""]
    if not report.missed_event_ids:
        lines.append("None — every detection opportunity was identified.")
    else:
        lines.append("| Event ID | Timestamp (UTC) | Severity | MITRE | What it was |")
        lines.append("|---|---|---|---|---|")
        events_by_id = {e.event_id: e for e in scenario.timeline}
        for event_id in report.missed_event_ids:
            event = events_by_id[event_id]
            mitre = (
                f"{event.mitre.technique_id} {event.mitre.technique_name}" if event.mitre else "—"
            )
            summary = event.description.strip().split("\n")[0][:90]
            lines.append(
                f"| `{event_id}` | {event.timestamp.isoformat()} | {event.severity.value} | "
                f"{mitre} | {summary} |"
            )

    lines += ["", "## False positives", ""]
    fps = [o for o in report.outcomes if o.verdict.startswith("false_positive")]
    if not fps:
        lines.append("None — everything flagged was genuinely part of the attack.")
    else:
        lines.append("| Flagged | Why it's a false positive |")
        lines.append("|---|---|")
        for outcome in fps:
            reason = (
                "no event with this ID exists in the scenario"
                if outcome.verdict == "false_positive_unknown"
                else "this event is benign/expected activity, not part of the attack"
            )
            lines.append(f"| `{outcome.event_id}` | {reason} |")

    lines += ["", "## Response time detail", ""]
    tps = [o for o in report.outcomes if o.verdict == "true_positive"]
    timed = [o for o in tps if o.latency_seconds is not None]
    if not timed:
        lines.append(
            "No `detected_at` timestamps were supplied in the submission, so response "
            "time could not be measured. (This is fine — it's optional.)"
        )
    else:
        lines.append("| Event ID | Occurred (UTC) | Detected (UTC) | Latency |")
        lines.append("|---|---|---|---|")
        for outcome in timed:
            lines.append(
                f"| `{outcome.event_id}` | "
                f"{outcome.event_timestamp.isoformat() if outcome.event_timestamp else 'n/a'} | "
                f"{outcome.detected_at.isoformat() if outcome.detected_at else 'n/a'} | "
                f"{_format_duration(outcome.latency_seconds)} |"
            )

    if report.answers:
        lines += [
            "",
            "## Written answers (manual review required)",
            "",
            "These are **not** auto-graded — compare against `instructor/ANSWER_KEY.md`.",
            "",
        ]
        answer_key = {item.id: item for item in scenario.answer_key}
        for qid, response in report.answers.items():
            question = answer_key[qid].question if qid in answer_key else "(unknown question id)"
            lines += [f"### {qid} — {question}", "", f"**Student answered:** {response or '(blank)'}", ""]

    lines.append("")
    return "\n".join(lines)
