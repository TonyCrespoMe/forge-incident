"""Heuristic semantic-consistency checker for LLM-generated scenarios.

`models.Scenario`'s Pydantic validation (see `models.py`,
`scenario_loader._build_scenario`) is *structural*: it guarantees every
event references a real actor/host, every MITRE technique ID is
well-formed, timestamps are sorted, and so on. It cannot know that "the
attacker's IP" should be the same string in event 3 and event 9 — that is
a semantic property of the *story*, not the schema.

This module is a best-effort, heuristic second pass over an already
schema-valid `Scenario`, looking for patterns that often indicate an LLM
silently re-invented a value it should have reused. It never raises and
never blocks generation — `llm/scenario_generator.py` surfaces its output
as warnings attached to `GeneratedScenario.warnings`, and the packager
surfaces them to the instructor. False positives are expected (e.g. a
victim's normal login IP legitimately appearing only once is fine); this
is a prompt for human review, not a correctness guarantee.
"""

from __future__ import annotations

from collections import Counter

from forge_incident.models import Difficulty, Scenario

__all__ = ["check_consistency"]

_EXPECTED_EVENT_COUNT_RANGE: dict[Difficulty, tuple[int, int]] = {
    Difficulty.BEGINNER: (6, 16),
    Difficulty.INTERMEDIATE: (12, 28),
    Difficulty.ADVANCED: (20, 45),
    # Lower bound aligned with tests/test_curriculum.py's sanity floor. Expert
    # difficulty is about incomplete and misleading evidence, not bulk -- a
    # 26-event scenario across four hosts with a real visibility gap is
    # genuinely expert, and warning about it would be noise.
    Difficulty.EXPERT: (25, 70),
}


def check_consistency(scenario: Scenario) -> list[str]:
    """Return a list of human-readable warnings; empty list means no concerns found."""
    warnings: list[str] = []
    warnings.extend(_check_unused_actors_and_hosts(scenario))
    warnings.extend(_check_single_occurrence_external_ips(scenario))
    warnings.extend(_check_filename_hash_mismatches(scenario))
    warnings.extend(_check_event_count_for_difficulty(scenario))
    warnings.extend(_check_answer_key_coverage(scenario))
    return warnings


def _check_unused_actors_and_hosts(scenario: Scenario) -> list[str]:
    """An actor/host defined but never referenced by any event is usually a sign
    the generator introduced an entity it then forgot to use consistently
    (or, less often, an intentional instructor-context-only entity — see
    the bundled gcp_key_compromise.yaml's `attacker` actor for a
    legitimate example — so this is a warning, not an error)."""
    warnings: list[str] = []
    used_actors = {e.actor for e in scenario.timeline if e.actor}
    used_hosts = {e.host for e in scenario.timeline if e.host}
    for key in scenario.actors:
        if key not in used_actors:
            warnings.append(
                f"Actor '{key}' is defined but never referenced by any timeline event "
                "(only legitimate if intentionally instructor-context-only, e.g. an "
                "unattributed external attacker)."
            )
    for key in scenario.hosts:
        if key not in used_hosts:
            warnings.append(f"Host '{key}' is defined but never referenced by any timeline event.")
    return warnings


def _check_single_occurrence_external_ips(scenario: Scenario) -> list[str]:
    """Collect every IP that shows up in a network/cloud payload. If exactly one
    appears only once while three or more distinct IPs appear across the
    timeline, it's often (not always) a sign an "attacker IP" was
    accidentally regenerated per-event instead of reused."""
    ip_counts: Counter[str] = Counter()
    for event in scenario.timeline:
        if event.network is not None:
            ip_counts[event.network.src_ip] += 1
            ip_counts[event.network.dst_ip] += 1
        if event.cloud is not None:
            ip_counts[event.cloud.caller_ip] += 1

    if len(ip_counts) < 3:
        return []

    singletons = [ip for ip, count in ip_counts.items() if count == 1]
    # A handful of legitimately-singleton IPs (e.g. varied benign traffic) is
    # normal; flag only when MOST distinct IPs are singletons, which is the
    # actual smell of "a fresh IP was invented every time."
    if len(singletons) >= max(3, int(len(ip_counts) * 0.6)):
        return [
            f"{len(singletons)} of {len(ip_counts)} distinct IP addresses across the "
            "timeline appear only once. If any of these are meant to be the same "
            "attacker/infrastructure IP recurring across multiple events, verify the "
            "exact string was reused rather than regenerated per event."
        ]
    return []


def _check_filename_hash_mismatches(scenario: Scenario) -> list[str]:
    """The same filename appearing with two different sha256 hashes (or vice
    versa: the same hash under two different filenames, which CAN be
    legitimate — e.g. a renamed dropped file — but is worth a second look)
    usually indicates the same conceptual artifact was described
    inconsistently."""
    warnings: list[str] = []
    filename_to_hashes: dict[str, set[str]] = {}
    hash_to_filenames: dict[str, set[str]] = {}
    for event in scenario.timeline:
        if event.file is not None and event.file.sha256:
            filename_to_hashes.setdefault(event.file.filename, set()).add(event.file.sha256)
            hash_to_filenames.setdefault(event.file.sha256, set()).add(event.file.filename)

    for filename, hashes in filename_to_hashes.items():
        if len(hashes) > 1:
            warnings.append(
                f"Filename '{filename}' appears with {len(hashes)} different sha256 hashes "
                "across the timeline — if this is meant to be the same file, its hash "
                "should be identical everywhere."
            )
    return warnings


def _check_event_count_for_difficulty(scenario: Scenario) -> list[str]:
    low, high = _EXPECTED_EVENT_COUNT_RANGE.get(scenario.difficulty, (0, 10_000))
    count = scenario.event_count
    if count < low or count > high:
        return [
            f"{count} timeline events is outside the typical range for "
            f"'{scenario.difficulty.value}' ({low}-{high}). Not necessarily wrong, but "
            "worth a quick pacing/scope review."
        ]
    return []


def _check_answer_key_coverage(scenario: Scenario) -> list[str]:
    if not scenario.answer_key:
        return ["No answer_key items were generated — an instructor package needs at least a few."]
    referenced = {eid for item in scenario.answer_key for eid in item.related_event_ids}
    if not referenced:
        return [
            "No answer_key item references any related_event_ids — answers won't be "
            "traceable back to specific log lines."
        ]
    return []
