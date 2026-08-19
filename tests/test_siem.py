"""Tests for the SIEM exporters (Splunk HEC, Elastic ECS bulk, Sentinel)."""

from __future__ import annotations

import json

import pytest

from forge_incident.scenario_loader import load_scenario
from forge_incident.siem import (
    ALL_EXPORTERS,
    EXPORTER_NAMES,
    UnknownExporterError,
    export_scenario,
    get_exporter,
)
from tests.conftest import SCENARIOS_DIR


def _export(scenario_file: str, formats=None) -> dict[str, str]:
    scenario = load_scenario(SCENARIOS_DIR / scenario_file)
    return {a.relative_path: a.content for a in export_scenario(scenario, formats)}


def test_every_exporter_has_a_unique_name_and_description():
    names = [e.name for e in ALL_EXPORTERS]
    assert len(names) == len(set(names))
    assert set(names) == set(EXPORTER_NAMES)
    for exporter in ALL_EXPORTERS:
        assert exporter.description.strip()


def test_get_exporter_is_case_insensitive():
    assert get_exporter("SPLUNK").name == "splunk"


def test_get_exporter_rejects_an_unknown_format():
    with pytest.raises(UnknownExporterError, match="Unknown SIEM export format"):
        get_exporter("qradar")


def test_splunk_export_is_valid_hec_envelopes(scenario_path):
    scenario = load_scenario(scenario_path)
    artifacts = export_scenario(scenario, ["splunk"])
    assert len(artifacts) == 1
    lines = [line for line in artifacts[0].content.splitlines() if line.strip()]
    assert len(lines) == scenario.event_count
    for line in lines:
        record = json.loads(line)
        assert isinstance(record["time"], float)
        assert record["sourcetype"].startswith("forge:")
        assert record["index"] == "forge_incident"
        assert record["event"]["scenario_id"] == scenario.scenario_id


def test_elastic_export_is_valid_bulk_ndjson(scenario_path):
    scenario = load_scenario(scenario_path)
    artifacts = export_scenario(scenario, ["elastic"])
    lines = [line for line in artifacts[0].content.splitlines() if line.strip()]
    # _bulk format alternates action line, document line.
    assert len(lines) == scenario.event_count * 2
    for index, line in enumerate(lines):
        obj = json.loads(line)
        if index % 2 == 0:
            assert "index" in obj and "_index" in obj["index"]
        else:
            assert "@timestamp" in obj
            assert obj["ecs"]["version"]
            assert isinstance(obj["event"]["category"], list)


def test_elastic_event_categories_use_the_ecs_controlled_vocabulary():
    """Arbitrary category strings break Kibana's prebuilt content."""
    allowed = {
        "authentication", "iam", "email", "malware", "process", "registry",
        "file", "network", "dns", "configuration", "intrusion_detection",
    }
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    artifacts = export_scenario(scenario, ["elastic"])
    for index, line in enumerate(artifacts[0].content.strip().splitlines()):
        if index % 2 == 1:
            for category in json.loads(line)["event"]["category"]:
                assert category in allowed, f"'{category}' is not a valid ECS event.category"


def test_sentinel_export_produces_rows_plus_starter_queries(scenario_path):
    scenario = load_scenario(scenario_path)
    artifacts = export_scenario(scenario, ["sentinel"])
    assert len(artifacts) == 2

    data = next(a for a in artifacts if a.relative_path.endswith(".json"))
    rows = json.loads(data.content)
    assert len(rows) == scenario.event_count
    for row in rows:
        assert "TimeGenerated" in row
        assert row["ScenarioId"] == scenario.scenario_id

    kql = next(a for a in artifacts if a.relative_path.endswith(".kql"))
    assert "ForgeIncident_CL" in kql.content
    assert scenario.scenario_id in kql.content


def test_export_defaults_to_every_format():
    artifacts = _export("phishing_to_exfil.yaml")
    paths = " ".join(artifacts)
    for platform in ("splunk", "elastic", "sentinel"):
        assert platform in paths


def test_siem_exports_never_leak_instructor_narrative(scenario_path):
    """`Event.description` is instructor-only in every output path."""
    scenario = load_scenario(scenario_path)
    blob = "\n".join(a.content for a in export_scenario(scenario))
    for event in scenario.timeline:
        snippet = event.description.strip().split("\n")[0][:30]
        assert snippet not in blob, f"description leaked for {event.event_id}"


def test_siem_exports_do_include_attack_mapping():
    """Deliberate, documented exception: a SIEM export without ATT&CK fields
    can't be used to validate detection content, which is the point of it."""
    artifacts = _export("phishing_to_exfil.yaml")
    blob = "\n".join(artifacts.values())
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    technique_ids = {e.mitre.technique_id for e in scenario.timeline if e.mitre}
    assert technique_ids
    for technique_id in technique_ids:
        assert technique_id in blob


def test_identifiers_match_between_siem_export_and_raw_logs():
    """A SIEM export and the student's raw logs must describe the same incident."""
    from forge_incident.emitters import run_all

    scenario = load_scenario(SCENARIOS_DIR / "gcp_key_compromise.yaml")
    raw_blob = "\n".join(a.content for a in run_all(scenario))
    siem_blob = "\n".join(a.content for a in export_scenario(scenario))

    attacker_ip = "185.220.101.47"
    assert attacker_ip in raw_blob
    assert attacker_ip in siem_blob
