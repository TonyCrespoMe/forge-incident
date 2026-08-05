"""Tests for scenario_loader.py against the real bundled YAML scenarios."""

from __future__ import annotations

import pytest

from forge_incident.scenario_loader import (
    ScenarioLoadError,
    derive_rng,
    list_scenarios,
    load_scenario,
)
from tests.conftest import SCENARIOS_DIR


def test_bundled_scenarios_load_and_validate(scenario_path):
    scenario = load_scenario(scenario_path)
    assert scenario.event_count > 0
    assert [e.timestamp for e in scenario.timeline] == sorted(
        e.timestamp for e in scenario.timeline
    )
    # student_briefing must exist and must not be the (spoiler-full) description
    assert scenario.student_briefing.strip()
    assert scenario.student_briefing != scenario.description


def test_seed_override_changes_seed_not_structure(scenario_path):
    a = load_scenario(scenario_path, seed=111)
    b = load_scenario(scenario_path, seed=222)
    assert a.seed == 111
    assert b.seed == 222
    assert [e.event_id for e in a.timeline] == [e.event_id for e in b.timeline]
    assert [e.event_type for e in a.timeline] == [e.event_type for e in b.timeline]


def test_same_seed_produces_identical_timestamps(scenario_path):
    a = load_scenario(scenario_path, seed=42)
    b = load_scenario(scenario_path, seed=42)
    assert [e.timestamp for e in a.timeline] == [e.timestamp for e in b.timeline]


def test_different_seed_can_change_jitter(scenario_path):
    a = load_scenario(scenario_path, seed=1)
    b = load_scenario(scenario_path, seed=2)
    # The *order* and *offsets from start_time* never change with seed, but
    # jitter is allowed to (and for a scenario with several events, some
    # jittered timestamp should differ across seeds almost always).
    a_ts = [e.timestamp for e in a.timeline]
    b_ts = [e.timestamp for e in b.timeline]
    assert a_ts != b_ts or len(a_ts) <= 1


def test_missing_file_raises_scenario_load_error():
    with pytest.raises(ScenarioLoadError):
        load_scenario(SCENARIOS_DIR / "does-not-exist.yaml")


def test_malformed_yaml_raises_scenario_load_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("scenario_id: [unterminated", encoding="utf-8")
    with pytest.raises(ScenarioLoadError):
        load_scenario(bad)


def test_missing_required_field_raises_scenario_load_error(tmp_path):
    bad = tmp_path / "incomplete.yaml"
    bad.write_text("scenario_id: incomplete\ntitle: X\n", encoding="utf-8")
    with pytest.raises(ScenarioLoadError):
        load_scenario(bad)


def test_list_scenarios_finds_both_bundled_scenarios():
    summaries = list_scenarios(SCENARIOS_DIR)
    ids = {s.scenario_id for s in summaries}
    assert {"phishing-to-exfil-01", "gcp-key-compromise-01"} <= ids
    assert all(s.is_valid for s in summaries), [s.error for s in summaries if not s.is_valid]


def test_list_scenarios_flags_invalid_file_without_raising(tmp_path):
    (tmp_path / "broken.yaml").write_text("title: no scenario_id or timeline\n", encoding="utf-8")
    summaries = list_scenarios(tmp_path)
    assert len(summaries) == 1
    assert summaries[0].is_valid is False
    assert summaries[0].error


def test_derive_rng_deterministic_and_independent():
    assert derive_rng(1, "a").random() == derive_rng(1, "a").random()
    assert derive_rng(1, "a").random() != derive_rng(1, "b").random()
    assert derive_rng(1, "a").random() != derive_rng(2, "a").random()
