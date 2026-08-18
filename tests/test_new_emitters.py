"""Tests for the Okta, CrowdStrike, and firewall-syslog emitters.

The point of these log sources is that they CORRELATE with the existing
ones — so beyond "does it render", these tests assert that an identifier
appearing in one source is byte-identical in every other source that
should carry it.
"""

from __future__ import annotations

import json

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.scenario_loader import load_scenario_from_text

_MULTI_SOURCE_YAML = """
scenario_id: multi-source-test
title: "Multi-source correlation"
description: >
  Instructor narrative that must never appear in any rendered log.
student_briefing: >
  Investigate the alerts.
difficulty: intermediate
seed: 7
organization:
  name: Testco Industries
  domain: testco.example
start_time: "2026-05-01T09:00:00Z"
actors:
  victim:
    username: jdoe
    email: jdoe@testco.example
    display_name: Jane Doe
hosts:
  ws01:
    hostname: TESTCO-WS01
    ip_address: 10.0.0.15
    host_type: workstation
    os: windows
timeline:
  - id: okta-fail
    at: "+0m"
    event_type: account_login_failure
    log_sources: [okta, firewall_syslog, palo_alto]
    severity: medium
    actor: victim
    host: ws01
    description: >
      Failed Okta login originating from the attacker's IP.
    network:
      protocol: tcp
      src_ip: 185.220.101.47
      src_port: 44100
      dst_ip: 10.0.0.15
      dst_port: 443
      action: allow
      app: ssl
      bytes_sent: 4096
      bytes_received: 812
  - id: okta-success
    at: "+3m"
    event_type: account_login_success
    log_sources: [okta]
    severity: high
    actor: victim
    description: >
      Successful login from the same attacker IP.
    network:
      protocol: tcp
      src_ip: 185.220.101.47
      src_port: 44210
      dst_ip: 10.0.0.15
      dst_port: 443
      action: allow
  - id: cs-detect
    at: "+9m"
    event_type: malware_execution
    log_sources: [crowdstrike, windows]
    severity: critical
    actor: victim
    host: ws01
    description: >
      Falcon detects malware execution on the workstation.
    mitre:
      technique_id: T1204.002
      technique_name: "Malicious File"
      tactic: Execution
    process:
      pid: 4812
      ppid: 3120
      name: powershell.exe
      command_line: "powershell.exe -enc SQBFAFgA"
      parent_name: winword.exe
      sha256: "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900"
"""

_ATTACKER_IP = "185.220.101.47"
_SHA256 = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900"


def _artifacts() -> dict[str, str]:
    scenario = load_scenario_from_text(_MULTI_SOURCE_YAML, seed=7)
    return {a.relative_path: a.content for a in run_all(scenario, BUILTIN_EMITTERS)}


def _content_for(artifacts: dict[str, str], source: str) -> str:
    return next(content for path, content in artifacts.items() if f"/{source}/" in path)


def test_all_three_new_sources_render():
    artifacts = _artifacts()
    for source in ("okta", "crowdstrike", "firewall_syslog"):
        content = _content_for(artifacts, source)
        assert content.strip(), f"{source} produced an empty artifact"


def test_okta_records_are_valid_json_lines_with_expected_fields():
    okta = _content_for(_artifacts(), "okta")
    lines = [line for line in okta.splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        record = json.loads(line)
        assert record["eventType"].startswith(("user.", "system.", "group.", "security."))
        assert record["actor"]["alternateId"] == "jdoe@testco.example"
        assert record["client"]["ipAddress"] == _ATTACKER_IP
        assert record["outcome"]["result"] in ("SUCCESS", "FAILURE")


def test_okta_outcome_reflects_success_versus_failure():
    okta = _content_for(_artifacts(), "okta")
    outcomes = [json.loads(line)["outcome"]["result"] for line in okta.strip().splitlines()]
    assert outcomes == ["FAILURE", "SUCCESS"]


def test_crowdstrike_detection_carries_process_and_attack_fields():
    crowdstrike = _content_for(_artifacts(), "crowdstrike")
    record = json.loads(crowdstrike.strip())
    body = record["event"]
    assert record["metadata"]["eventType"] == "DetectionSummaryEvent"
    assert body["ComputerName"] == "TESTCO-WS01"
    assert body["UserName"] == "jdoe"
    assert body["ProcessId"] == 4812
    assert body["SHA256HashData"] == _SHA256
    # A real Falcon console does show ATT&CK on a detection -- see the
    # emitter's docstring for why this is a deliberate exception.
    assert body["TechniqueId"] == "T1204.002"


def test_firewall_syslog_is_key_value_with_matching_network_fields():
    firewall = _content_for(_artifacts(), "firewall_syslog")
    line = firewall.strip().splitlines()[0]
    fields = dict(
        part.split("=", 1) for part in line.split(" ") if "=" in part and not part.startswith('"')
    )
    assert fields["srcip"] == _ATTACKER_IP
    assert fields["dstip"] == "10.0.0.15"
    assert fields["srcport"] == "44100"
    assert fields["dstport"] == "443"
    assert fields["action"] == "accept"
    assert fields["sentbyte"] == "4096"
    assert fields["rcvdbyte"] == "812"


def test_attacker_ip_is_identical_across_okta_firewall_and_palo_alto():
    """The whole point of adding these sources: one pivot works everywhere."""
    artifacts = _artifacts()
    for source in ("okta", "firewall_syslog", "palo_alto"):
        assert _ATTACKER_IP in _content_for(artifacts, source), f"IP missing from {source}"


def test_process_identifiers_identical_across_crowdstrike_and_windows():
    artifacts = _artifacts()
    crowdstrike = _content_for(artifacts, "crowdstrike")
    windows = _content_for(artifacts, "windows")
    for identifier in ("4812", "3120", _SHA256, "powershell.exe"):
        assert identifier in crowdstrike, f"{identifier} missing from CrowdStrike"
        assert identifier in windows, f"{identifier} missing from Windows"


def test_new_emitters_never_leak_instructor_narrative():
    scenario = load_scenario_from_text(_MULTI_SOURCE_YAML, seed=7)
    artifacts = run_all(scenario, BUILTIN_EMITTERS)
    blob = "\n".join(a.content for a in artifacts)
    for event in scenario.timeline:
        snippet = event.description.strip().split("\n")[0][:30]
        assert snippet not in blob, f"description leaked for {event.event_id}"


def test_emitters_with_no_relevant_events_produce_nothing():
    """A scenario that uses none of the new sources must not emit empty files."""
    scenario = load_scenario_from_text(
        _MULTI_SOURCE_YAML.replace("[okta, firewall_syslog, palo_alto]", "[palo_alto]")
        .replace("log_sources: [okta]", "log_sources: [palo_alto]")
        .replace("[crowdstrike, windows]", "[windows]"),
        seed=7,
    )
    paths = [a.relative_path for a in run_all(scenario, BUILTIN_EMITTERS)]
    assert not any("okta" in p or "crowdstrike" in p or "firewall_syslog" in p for p in paths)
