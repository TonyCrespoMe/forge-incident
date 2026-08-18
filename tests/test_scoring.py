"""Tests for scoring.py: detection coverage, false positives, response time."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from forge_incident.scenario_loader import load_scenario, load_scenario_from_text
from forge_incident.scoring import (
    Detection,
    Submission,
    SubmissionError,
    default_is_opportunity,
    load_submission,
    render_report_markdown,
    score_submission,
    submission_template,
)
from tests.conftest import SCENARIOS_DIR

# A scenario with a deliberate mix of malicious AND benign events, so
# false-positive scoring is actually exercised (the bundled scenarios are
# all-malicious by design, which can't test precision).
_MIXED_YAML = """
scenario_id: scoring-test
title: "Scoring test"
description: >
  Instructor narrative.
student_briefing: >
  Investigate.
difficulty: beginner
seed: 11
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
  - id: benign-login
    at: "+0m"
    event_type: account_login_success
    log_sources: [windows]
    severity: info
    actor: victim
    host: ws01
    description: >
      Normal morning login. Not part of the attack.
  - id: benign-file
    at: "+5m"
    event_type: file_created
    log_sources: [windows]
    severity: info
    actor: victim
    host: ws01
    description: >
      User saves a legitimate document.
  - id: malware
    at: "+30m"
    event_type: malware_execution
    log_sources: [windows]
    severity: critical
    actor: victim
    host: ws01
    description: >
      Malware executes.
    mitre:
      technique_id: T1204.002
      technique_name: "Malicious File"
      tactic: Execution
  - id: exfil
    at: "+90m"
    event_type: data_exfiltration
    log_sources: [windows]
    severity: critical
    actor: victim
    host: ws01
    description: >
      Data leaves the network.
    mitre:
      technique_id: T1041
      technique_name: "Exfiltration Over C2 Channel"
      tactic: Exfiltration
answer_key:
  - id: q1
    question: "What happened?"
    answer: >
      Malware ran and data was exfiltrated.
    related_event_ids: [malware, exfil]
    points: 2
"""


def _mixed_scenario():
    return load_scenario_from_text(_MIXED_YAML, seed=11)


def test_default_opportunity_rule_splits_malicious_from_benign():
    scenario = _mixed_scenario()
    opportunities = {e.event_id for e in scenario.timeline if default_is_opportunity(e)}
    assert opportunities == {"malware", "exfil"}


def test_perfect_submission_scores_full_coverage_and_precision():
    scenario = _mixed_scenario()
    submission = Submission(
        analyst="Ace",
        detections=[Detection("malware"), Detection("exfil")],
    )
    report = score_submission(scenario, submission)
    assert report.coverage_pct == 100.0
    assert report.precision_pct == 100.0
    assert report.missed_event_ids == []
    assert report.false_positive_count == 0


def test_flagging_a_benign_event_is_a_false_positive():
    scenario = _mixed_scenario()
    submission = Submission(
        detections=[Detection("malware"), Detection("exfil"), Detection("benign-login")]
    )
    report = score_submission(scenario, submission)
    assert report.coverage_pct == 100.0
    assert report.false_positive_count == 1
    assert report.precision_pct == pytest.approx(66.7, abs=0.1)


def test_unknown_event_id_is_tracked_separately_from_benign_false_positives():
    scenario = _mixed_scenario()
    submission = Submission(detections=[Detection("malware"), Detection("no-such-event")])
    report = score_submission(scenario, submission)
    assert report.unknown_event_id_count == 1
    assert report.false_positive_count == 0
    verdicts = {o.event_id: o.verdict for o in report.outcomes}
    assert verdicts["no-such-event"] == "false_positive_unknown"


def test_missed_opportunities_are_listed():
    scenario = _mixed_scenario()
    report = score_submission(scenario, Submission(detections=[Detection("malware")]))
    assert report.missed_event_ids == ["exfil"]
    assert report.coverage_pct == 50.0


def test_coverage_by_tactic_reports_missed_tactics_as_zero():
    """A tactic the student entirely missed must still appear, as 0/N."""
    scenario = _mixed_scenario()
    report = score_submission(scenario, Submission(detections=[Detection("malware")]))
    assert report.coverage_by_tactic["Execution"] == (1, 1)
    assert report.coverage_by_tactic["Exfiltration"] == (0, 1)


def test_response_time_measures_latency_and_time_to_first_detection():
    scenario = _mixed_scenario()
    by_id = {e.event_id: e for e in scenario.timeline}
    submission = Submission(
        detections=[
            Detection("malware", by_id["malware"].timestamp + timedelta(minutes=10)),
            Detection("exfil", by_id["exfil"].timestamp + timedelta(minutes=30)),
        ]
    )
    report = score_submission(scenario, submission)
    assert report.latencies == [600.0, 1800.0]
    assert report.mean_latency_seconds == 1200.0
    assert report.median_latency_seconds == 1200.0
    # First malicious event is `malware`; earliest detection is 10 min later.
    assert report.time_to_first_detection_seconds == 600.0


def test_response_time_is_none_when_no_timestamps_supplied():
    scenario = _mixed_scenario()
    report = score_submission(scenario, Submission(detections=[Detection("malware")]))
    assert report.time_to_first_detection_seconds is None
    assert report.mean_latency_seconds is None


def test_duplicate_detections_count_once_toward_coverage():
    scenario = _mixed_scenario()
    submission = Submission(detections=[Detection("malware"), Detection("malware")])
    report = score_submission(scenario, submission)
    assert report.detected_count == 1
    assert report.coverage_by_tactic["Execution"] == (1, 1)


def test_empty_submission_scores_zero_without_crashing():
    scenario = _mixed_scenario()
    report = score_submission(scenario, Submission())
    assert report.coverage_pct == 0.0
    assert report.precision_pct == 0.0
    assert len(report.missed_event_ids) == 2


def test_report_to_dict_is_json_serializable():
    scenario = _mixed_scenario()
    report = score_submission(scenario, Submission(detections=[Detection("malware")]))
    payload = json.dumps(report.to_dict())
    assert "detection_coverage" in payload
    assert "false_positives" in payload
    assert "response_time" in payload


def test_markdown_report_contains_each_section():
    scenario = _mixed_scenario()
    report = score_submission(
        scenario, Submission(analyst="Ace", detections=[Detection("malware"), Detection("benign-file")])
    )
    markdown = render_report_markdown(report, scenario)
    for heading in (
        "# Score Report",
        "## Summary",
        "## Detection coverage by ATT&CK tactic",
        "## Missed detection opportunities",
        "## False positives",
    ):
        assert heading in markdown


def test_submission_template_is_spoiler_free(scenario_path):
    """The template ships inside the STUDENT package, so it must not reveal
    which events are malicious or leak any instructor narrative.

    Event ids are checked as bounded tokens: `exfil` is legitimately a
    substring of the scenario id `phishing-to-exfil-01`, and that isn't a
    leak — same word-boundary approach test_emitters.py uses.
    """
    import re

    scenario = load_scenario(scenario_path)
    template = submission_template(scenario)

    assert scenario.scenario_id in template
    for event in scenario.timeline:
        pattern = rf"(?<![\w.-]){re.escape(event.event_id)}(?![\w.-])"
        assert not re.search(pattern, template), f"template leaked event id {event.event_id}"
        snippet = event.description.strip().split("\n")[0][:30]
        assert snippet not in template, "template leaked instructor narrative"
    for item in scenario.answer_key:
        assert item.answer.strip()[:25] not in template, "template leaked an answer"


def test_submission_template_round_trips_through_the_loader(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    path = tmp_path / "submission.json"
    path.write_text(submission_template(scenario), encoding="utf-8")
    submission = load_submission(path)
    assert submission.scenario_id == scenario.scenario_id
    assert set(submission.answers) == {item.id for item in scenario.answer_key}


def test_load_submission_accepts_plain_event_id_strings(tmp_path):
    path = tmp_path / "submission.json"
    path.write_text(json.dumps({"analyst": "A", "detections": ["malware", "exfil"]}))
    submission = load_submission(path)
    assert [d.event_id for d in submission.detections] == ["malware", "exfil"]


def test_load_submission_rejects_a_bad_timestamp(tmp_path):
    path = tmp_path / "submission.json"
    path.write_text(
        json.dumps({"detections": [{"event_id": "malware", "detected_at": "not-a-date"}]})
    )
    with pytest.raises(SubmissionError, match="ISO-8601"):
        load_submission(path)


def test_load_submission_rejects_a_detection_without_an_event_id(tmp_path):
    path = tmp_path / "submission.json"
    path.write_text(json.dumps({"detections": [{"notes": "forgot the id"}]}))
    with pytest.raises(SubmissionError, match="event_id"):
        load_submission(path)


def test_load_submission_reports_a_missing_file():
    with pytest.raises(SubmissionError, match="not found"):
        load_submission("/nonexistent/submission.json")
