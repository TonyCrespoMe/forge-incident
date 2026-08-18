"""Tests for the web UI's scenario round-tripping.

Streamlit is NOT required to run these — `webui/scenario_io.py` is
deliberately free of Streamlit imports precisely so the risky part of a
timeline editor (does an edit survive the trip back to valid YAML?) is
testable in the normal offline suite.
"""

from __future__ import annotations

from forge_incident.scenario_loader import load_scenario, load_scenario_from_text
from forge_incident.webui.scenario_io import (
    TIMELINE_COLUMNS,
    dangling_answer_key_refs,
    offset_from_start,
    prune_dangling_answer_key_refs,
    raw_to_yaml,
    rows_to_timeline,
    scenario_to_raw,
    timeline_to_rows,
)


def _payload_count(scenario) -> int:
    return sum(
        1
        for event in scenario.timeline
        for field in ("process", "email", "network", "cloud", "file")
        if getattr(event, field) is not None
    )


def test_scenario_survives_a_full_yaml_round_trip(scenario_path):
    original = load_scenario(scenario_path)
    restored = load_scenario_from_text(
        raw_to_yaml(scenario_to_raw(original)), seed=original.seed
    )

    assert restored.scenario_id == original.scenario_id
    assert restored.title == original.title
    assert restored.difficulty == original.difficulty
    assert restored.event_count == original.event_count
    assert [e.event_type for e in restored.timeline] == [e.event_type for e in original.timeline]
    assert [e.log_sources for e in restored.timeline] == [e.log_sources for e in original.timeline]
    assert [e.actor for e in restored.timeline] == [e.actor for e in original.timeline]
    assert [e.host for e in restored.timeline] == [e.host for e in original.timeline]
    assert len(restored.answer_key) == len(original.answer_key)


def test_typed_payloads_survive_the_round_trip(scenario_path):
    """The bug a naive editor would ship: dropping process/email/network blocks."""
    original = load_scenario(scenario_path)
    restored = load_scenario_from_text(
        raw_to_yaml(scenario_to_raw(original)), seed=original.seed
    )
    assert _payload_count(restored) == _payload_count(original)
    assert _payload_count(original) > 0, "test scenario should exercise payloads"


def test_mitre_mappings_survive_the_round_trip(scenario_path):
    original = load_scenario(scenario_path)
    restored = load_scenario_from_text(
        raw_to_yaml(scenario_to_raw(original)), seed=original.seed
    )
    before = [e.mitre.technique_id for e in original.timeline if e.mitre]
    after = [e.mitre.technique_id for e in restored.timeline if e.mitre]
    assert before == after


def test_timeline_rows_expose_exactly_the_editor_columns(scenario_path):
    raw = scenario_to_raw(load_scenario(scenario_path))
    rows = timeline_to_rows(raw)
    assert len(rows) == len(raw["timeline"])
    for row in rows:
        assert set(row) == set(TIMELINE_COLUMNS)


def test_editing_a_cell_updates_only_that_field(scenario_path):
    original = load_scenario(scenario_path)
    raw = scenario_to_raw(original)
    rows = timeline_to_rows(raw)
    rows[0]["severity"] = "critical"
    rows[0]["description"] = "EDITED"

    raw["timeline"] = rows_to_timeline(rows, raw["timeline"])
    restored = load_scenario_from_text(raw_to_yaml(raw), seed=original.seed)

    assert restored.timeline[0].severity.value == "critical"
    assert restored.timeline[0].description.strip() == "EDITED"
    # Everything else about that event is untouched.
    assert restored.timeline[0].event_type == original.timeline[0].event_type
    assert restored.timeline[0].actor == original.timeline[0].actor
    assert _payload_count(restored) == _payload_count(original)


def test_adding_a_row_adds_an_event():
    scenario = load_scenario_from_text(_MINIMAL_YAML, seed=5)
    raw = scenario_to_raw(scenario)
    rows = timeline_to_rows(raw)
    rows.append(
        {
            "id": "new-event",
            "at": "+30m",
            "event_type": "data_exfiltration",
            "log_sources": "windows",
            "severity": "critical",
            "actor": "victim",
            "host": "ws01",
            "description": "Newly added event.",
        }
    )
    raw["timeline"] = rows_to_timeline(rows, raw["timeline"])
    restored = load_scenario_from_text(raw_to_yaml(raw), seed=5)

    assert restored.event_count == scenario.event_count + 1
    assert restored.timeline[-1].event_id == "new-event"
    assert restored.timeline[-1].event_type.value == "data_exfiltration"


def test_blank_rows_are_ignored():
    """`st.data_editor(num_rows="dynamic")` hands back empty trailing rows."""
    scenario = load_scenario_from_text(_MINIMAL_YAML, seed=5)
    raw = scenario_to_raw(scenario)
    rows = timeline_to_rows(raw)
    rows.append({column: "" for column in TIMELINE_COLUMNS})

    merged = rows_to_timeline(rows, raw["timeline"])
    assert len(merged) == len(raw["timeline"])


def test_deleting_a_referenced_event_is_detected_and_fixable(scenario_path):
    """Deleting a row the answer key points at would otherwise fail validation
    only AFTER the user finished editing — the UI catches it up front."""
    original = load_scenario(scenario_path)
    raw = scenario_to_raw(original)

    referenced = {
        ref for item in raw["answer_key"] for ref in (item.get("related_event_ids") or [])
    }
    assert referenced, "test scenario should have answer-key references"
    victim = sorted(referenced)[0]

    rows = [row for row in timeline_to_rows(raw) if row["id"] != victim]
    raw["timeline"] = rows_to_timeline(rows, raw["timeline"])

    dangling = dangling_answer_key_refs(raw)
    assert any(victim in refs for refs in dangling.values())

    cleaned = prune_dangling_answer_key_refs(raw)
    assert dangling_answer_key_refs(cleaned) == {}

    restored = load_scenario_from_text(raw_to_yaml(cleaned), seed=original.seed)
    assert restored.event_count == original.event_count - 1
    # Questions are kept; only the broken pointers were removed.
    assert len(restored.answer_key) == len(original.answer_key)


def test_a_clean_scenario_has_no_dangling_references(scenario_path):
    raw = scenario_to_raw(load_scenario(scenario_path))
    assert dangling_answer_key_refs(raw) == {}


def test_offset_formatting_round_trips_through_the_loader():
    scenario = load_scenario_from_text(_MINIMAL_YAML, seed=5)
    start = scenario.start_time
    for event in scenario.timeline:
        offset = offset_from_start(event.timestamp, start)
        assert offset[0] in "+-"
        assert any(unit in offset for unit in ("d", "h", "m", "s"))


_MINIMAL_YAML = """
scenario_id: webui-test
title: "Web UI test"
description: >
  Instructor narrative.
student_briefing: >
  Investigate.
difficulty: beginner
seed: 5
organization:
  name: Testco
  domain: testco.example
start_time: "2026-05-01T09:00:00Z"
actors:
  victim:
    username: jdoe
    email: jdoe@testco.example
    display_name: Jane Doe
hosts:
  ws01:
    hostname: WS01
    ip_address: 10.0.0.5
    os: windows
timeline:
  - id: e1
    at: "+0m"
    event_type: account_login_success
    log_sources: [windows]
    severity: info
    actor: victim
    host: ws01
    description: >
      A login.
  - id: e2
    at: "+10m"
    event_type: malware_execution
    log_sources: [windows]
    severity: critical
    actor: victim
    host: ws01
    description: >
      Malware runs.
    process:
      pid: 100
      name: evil.exe
      command_line: "evil.exe --run"
"""
