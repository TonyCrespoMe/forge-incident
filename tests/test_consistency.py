"""Tests for llm/consistency.py's heuristic semantic-consistency checks.

These are best-effort warnings, not schema validation (see the module
docstring) — tests here confirm each check fires on a crafted example and
stays quiet on the bundled, hand-authored scenarios (which are assumed
internally consistent by construction).
"""

from __future__ import annotations

from forge_incident.llm.consistency import check_consistency
from forge_incident.scenario_loader import load_scenario, load_scenario_from_text
from tests.conftest import SCENARIOS_DIR

_BASE_YAML = """
scenario_id: consistency-test
title: "Consistency Test"
description: >
  Test scenario for the consistency checker.
student_briefing: >
  Test briefing.
difficulty: intermediate
seed: 1
organization:
  name: Testco
  domain: testco.example
start_time: "2026-05-01T09:00:00Z"
actors:
  attacker:
    username: unknown
    email: unknown@unknown.external
    display_name: Unknown
hosts:
  web01:
    hostname: SRV-01
    ip_address: 10.0.0.5
    host_type: server
    os: linux
timeline:
{timeline}
answer_key:
{answer_key}
"""


_DEFAULT_ANSWER_KEY = "  - id: q1\n    question: q\n    answer: a\n    related_event_ids: [e1]\n"
_TWO_EVENT_ANSWER_KEY = (
    "  - id: q1\n    question: q\n    answer: a\n    related_event_ids: [e1, e2]\n"
)


def _build(timeline_yaml: str, answer_key_yaml: str = _DEFAULT_ANSWER_KEY) -> str:
    return _BASE_YAML.format(timeline=timeline_yaml, answer_key=answer_key_yaml)


def test_bundled_scenarios_produce_no_unused_actor_or_host_warnings():
    for filename in ("phishing_to_exfil.yaml", "gcp_key_compromise.yaml"):
        scenario = load_scenario(SCENARIOS_DIR / filename)
        warnings = check_consistency(scenario)
        unused_warnings = [w for w in warnings if "never referenced" in w]
        # gcp_key_compromise.yaml intentionally has one unattributed
        # instructor-context-only actor ("attacker") — everything else
        # must be referenced.
        assert len(unused_warnings) <= 1, unused_warnings


def test_unused_host_triggers_a_warning():
    yaml_text = _BASE_YAML.replace(
        "hosts:\n  web01:",
        "hosts:\n  web01:\n    hostname: SRV-01\n    ip_address: 10.0.0.5\n  unused-host:",
    ).format(
        timeline=(
            "  - id: e1\n"
            "    at: \"+0m\"\n"
            "    event_type: alert_triggered\n"
            "    log_sources: [linux]\n"
            "    severity: info\n"
            "    description: test\n"
        ),
        answer_key="  - id: q1\n    question: q\n    answer: a\n    related_event_ids: [e1]\n",
    )
    scenario = load_scenario_from_text(yaml_text, seed=1)
    warnings = check_consistency(scenario)
    assert any("unused-host" in w for w in warnings)


def test_filename_with_two_different_hashes_triggers_a_warning():
    timeline = (
        "  - id: e1\n"
        "    at: \"+0m\"\n"
        "    event_type: file_created\n"
        "    log_sources: [linux]\n"
        "    severity: info\n"
        "    host: web01\n"
        "    description: test\n"
        "    file:\n"
        "      path: /tmp/a\n"
        "      filename: dump.csv\n"
        f"      sha256: \"{'a' * 64}\"\n"
        "  - id: e2\n"
        "    at: \"+1m\"\n"
        "    event_type: file_modified\n"
        "    log_sources: [linux]\n"
        "    severity: info\n"
        "    host: web01\n"
        "    description: test\n"
        "    file:\n"
        "      path: /tmp/a\n"
        "      filename: dump.csv\n"
        f"      sha256: \"{'b' * 64}\"\n"
    )
    yaml_text = _build(timeline, _TWO_EVENT_ANSWER_KEY)
    scenario = load_scenario_from_text(yaml_text, seed=1)
    warnings = check_consistency(scenario)
    assert any("different sha256 hashes" in w for w in warnings)


def test_same_filename_same_hash_does_not_trigger_a_warning():
    digest = "c" * 64
    timeline = (
        "  - id: e1\n"
        "    at: \"+0m\"\n"
        "    event_type: file_created\n"
        "    log_sources: [linux]\n"
        "    severity: info\n"
        "    host: web01\n"
        "    description: test\n"
        "    file:\n"
        "      path: /tmp/a\n"
        "      filename: dump.csv\n"
        f"      sha256: \"{digest}\"\n"
        "  - id: e2\n"
        "    at: \"+1m\"\n"
        "    event_type: file_modified\n"
        "    log_sources: [linux]\n"
        "    severity: info\n"
        "    host: web01\n"
        "    description: test\n"
        "    file:\n"
        "      path: /tmp/a\n"
        "      filename: dump.csv\n"
        f"      sha256: \"{digest}\"\n"
    )
    yaml_text = _build(timeline, _TWO_EVENT_ANSWER_KEY)
    scenario = load_scenario_from_text(yaml_text, seed=1)
    warnings = check_consistency(scenario)
    assert not any("different sha256 hashes" in w for w in warnings)


def test_missing_answer_key_triggers_a_warning():
    timeline = (
        "  - id: e1\n"
        "    at: \"+0m\"\n"
        "    event_type: alert_triggered\n"
        "    log_sources: [linux]\n"
        "    severity: info\n"
        "    description: test\n"
    )
    yaml_text = _build(timeline, answer_key_yaml="  []\n")
    scenario = load_scenario_from_text(yaml_text, seed=1)
    warnings = check_consistency(scenario)
    assert any("No answer_key items" in w for w in warnings)


def test_check_consistency_never_raises_on_bundled_scenarios():
    for filename in ("phishing_to_exfil.yaml", "gcp_key_compromise.yaml"):
        scenario = load_scenario(SCENARIOS_DIR / filename)
        # Should return a list (possibly empty), never throw.
        assert isinstance(check_consistency(scenario), list)
