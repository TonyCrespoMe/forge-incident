"""Tests for emitters/ against the real bundled YAML scenarios.

Beyond "does it crash", these specifically guard the two properties the
whole project depends on: emitters never leak instructor-only content
into student-visible logs, and identifiers stay consistent across every
log format a scenario touches.
"""

from __future__ import annotations

import re

from forge_incident.emitters import run_all
from forge_incident.scenario_loader import load_scenario
from tests.conftest import SCENARIOS_DIR


def test_emitters_produce_nonempty_artifacts(scenario_path):
    scenario = load_scenario(scenario_path)
    artifacts = run_all(scenario)
    assert artifacts
    for artifact in artifacts:
        assert artifact.relative_path.startswith("logs/")
        assert artifact.content.strip()


def test_every_log_source_used_by_the_scenario_has_an_artifact(scenario_path):
    scenario = load_scenario(scenario_path)
    used_sources = {source for event in scenario.timeline for source in event.log_sources}
    produced_sources = {a.relative_path.split("/")[1] for a in run_all(scenario)}
    assert {s.value for s in used_sources} == produced_sources


def test_no_instructor_only_narrative_leaks_into_rendered_logs(scenario_path):
    """`Event.description` text and semantic `event_id`s (e.g. 'c2-beacon')
    must never appear verbatim in a rendered artifact — see emitters/base.py
    and windows.py/linux.py's docstrings for why. We check event_id as a
    bounded token so incidental substrings (e.g. 'staging' inside a real
    filename like 'staging.zip') don't count as a leak.
    """
    scenario = load_scenario(scenario_path)
    blob = "\n".join(a.content for a in run_all(scenario))

    for event in scenario.timeline:
        description_snippet = event.description.strip().split("\n")[0][:30]
        assert description_snippet not in blob, (
            f"description leaked for event {event.event_id!r}"
        )
        pattern = rf"(?<![\w.-]){re.escape(event.event_id)}(?![\w.-])"
        assert not re.search(pattern, blob), f"event_id {event.event_id!r} leaked verbatim"


def test_cross_log_identifier_consistency_gcp_scenario():
    """The attacker IP in the GCP compromise scenario must show up
    identically in both logs it appears in — the entire point of the tool.
    """
    scenario = load_scenario(SCENARIOS_DIR / "gcp_key_compromise.yaml")
    artifacts = {a.relative_path: a.content for a in run_all(scenario)}
    attacker_ip = "185.220.101.47"

    gcp_content = next(c for path, c in artifacts.items() if "gcp_audit" in path)
    linux_content = next(c for path, c in artifacts.items() if "linux" in path)

    assert attacker_ip in gcp_content
    assert attacker_ip in linux_content


def test_windows_xml_is_well_formed():
    import xml.etree.ElementTree as ET

    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    artifacts = [a for a in run_all(scenario) if a.relative_path.endswith(".xml")]
    assert artifacts
    for artifact in artifacts:
        ET.fromstring(artifact.content)  # raises ParseError if malformed


def test_csv_artifacts_are_parseable():
    import csv
    import io

    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    artifacts = [a for a in run_all(scenario) if a.relative_path.endswith(".csv")]
    assert artifacts
    for artifact in artifacts:
        rows = list(csv.DictReader(io.StringIO(artifact.content)))
        assert rows


def test_jsonl_artifacts_are_parseable():
    import json

    scenario = load_scenario(SCENARIOS_DIR / "gcp_key_compromise.yaml")
    artifacts = [a for a in run_all(scenario) if a.relative_path.endswith(".jsonl")]
    assert artifacts
    for artifact in artifacts:
        lines = [line for line in artifact.content.splitlines() if line.strip()]
        assert lines
        for line in lines:
            json.loads(line)


_CLOUD_YAML_TEMPLATE = """
scenario_id: cloud-emitter-test
title: "Cloud emitter test"
description: >
  Test.
student_briefing: >
  Test briefing.
difficulty: beginner
seed: 5
organization:
  name: Testco
  domain: testco.example
start_time: "2026-05-01T09:00:00Z"
actors:
  attacker:
    username: unknown
    email: unknown@unknown.external
    display_name: Unknown
timeline:
  - id: e1
    at: "+0m"
    event_type: cloud_api_call
    log_sources: [{log_source}]
    severity: high
    actor: attacker
    description: test
    cloud:
      method_name: ListBuckets
      service_name: example.amazonaws.com
      resource_name: "*"
      caller_ip: 185.220.101.47
      status_code: "OK"
      region: us-east-1
"""


def test_aws_cloudtrail_emitter_produces_valid_jsonl():
    import json

    from forge_incident.scenario_loader import load_scenario_from_text

    scenario = load_scenario_from_text(_CLOUD_YAML_TEMPLATE.format(log_source="aws_cloudtrail"), seed=5)
    artifacts = run_all(scenario)
    assert len(artifacts) == 1
    assert artifacts[0].relative_path.startswith("logs/aws_cloudtrail/")
    record = json.loads(artifacts[0].content.strip().splitlines()[0])
    assert record["eventName"] == "ListBuckets"
    assert record["sourceIPAddress"] == "185.220.101.47"
    assert record["awsRegion"] == "us-east-1"


def test_azure_activity_emitter_produces_valid_jsonl():
    import json

    from forge_incident.scenario_loader import load_scenario_from_text

    scenario = load_scenario_from_text(_CLOUD_YAML_TEMPLATE.format(log_source="azure_activity"), seed=5)
    artifacts = run_all(scenario)
    assert len(artifacts) == 1
    assert artifacts[0].relative_path.startswith("logs/azure_activity/")
    record = json.loads(artifacts[0].content.strip().splitlines()[0])
    assert record["operationName"] == "ListBuckets"
    assert record["callerIpAddress"] == "185.220.101.47"
