"""Tests for the bundled cryptomining_cloud_compromise.yaml scenario.

Two claims this scenario makes that must hold in the rendered artifacts,
not just in its prose:

1. The SSH brute-force attacker IP (192.0.2.55) never appears anywhere in
   the AWS CloudTrail evidence -- only the compromised instance's own IP
   does, because the stolen credentials are instance-scoped and every
   subsequent AWS call has to originate from the instance itself.
2. The two legitimate and two malicious RunInstances calls are
   distinguishable by caller identity and instance type, not by anything
   that would require an alert to already exist.
"""

from __future__ import annotations

import json

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.scenario_loader import load_scenario
from tests.conftest import SCENARIOS_DIR

SCENARIO_FILE = SCENARIOS_DIR / "cryptomining_cloud_compromise.yaml"

_SSH_ATTACKER_IP = "192.0.2.55"
_INSTANCE_OWN_IP = "203.0.113.240"


def _artifacts(scenario):
    return {a.relative_path: a.content for a in run_all(scenario, BUILTIN_EMITTERS)}


def _linux_log(artifacts) -> str:
    return next(c for p, c in artifacts.items() if "/linux/" in p)


def _cloudtrail_records(artifacts) -> list[dict]:
    content = next(c for p, c in artifacts.items() if "/aws_cloudtrail/" in p)
    return [json.loads(line) for line in content.strip().splitlines()]


def test_scenario_loads():
    scenario = load_scenario(SCENARIO_FILE)
    assert scenario.scenario_id == "cryptomining-cloud-compromise-01"


def test_ssh_burst_renders_as_63_failed_attempts_then_one_success():
    scenario = load_scenario(SCENARIO_FILE)
    linux_log = _linux_log(_artifacts(scenario))
    failed = [ln for ln in linux_log.splitlines() if "Failed password for deploy" in ln]
    accepted = [ln for ln in linux_log.splitlines() if "Accepted password for deploy" in ln]
    assert len(failed) == 63
    assert len(accepted) == 1
    assert all(_SSH_ATTACKER_IP in ln for ln in failed)
    assert _SSH_ATTACKER_IP in accepted[0]


def test_all_attacker_commands_render_with_full_command_line_intact():
    """Every attacker-run process on the compromised host must show its
    real command in the log -- if any of these used an EventType other
    than process_created, the linux emitter's fallback path would render
    a generic humanized label instead and the actual evidence would be
    lost. See emitters/linux.py: only PROCESS_CREATED renders command_line."""
    scenario = load_scenario(SCENARIO_FILE)
    linux_log = _linux_log(_artifacts(scenario))
    for needle in (
        "whoami && id && sudo -l",
        "169.254.169.254/latest/meta-data/iam/security-credentials/lucid-worker-role",
        "cdn-mirror-assets.example/pkg/update.tar.gz",
        "stratum+tcp://pool.minexmr-relay.example:4444",
    ):
        assert needle in linux_log, f"expected command fragment not found in rendered log: {needle}"
    assert "forge-incident[" not in linux_log, (
        "a generic fallback line appeared -- an attacker action's real command was lost"
    )


def test_ssh_attacker_ip_never_appears_in_cloudtrail():
    """The scenario's central claim: instance-scoped credentials mean the
    attacker's real-world origin is structurally absent from the AWS-side
    evidence, not just hard to find."""
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(_artifacts(scenario))
    for record in records:
        assert record["sourceIPAddress"] != _SSH_ATTACKER_IP


def test_malicious_runinstances_calls_originate_from_the_instances_own_ip():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(_artifacts(scenario))
    malicious = [
        r for r in records if r["userIdentity"]["userName"].startswith("lucid-worker-role")
    ]
    assert len(malicious) == 2
    assert all(r["sourceIPAddress"] == _INSTANCE_OWN_IP for r in malicious)
    assert all("g4dn" in r["requestParameters"]["resourceName"] for r in malicious)


def test_legitimate_autoscaling_calls_show_the_service_not_a_host():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(_artifacts(scenario))
    legit = [r for r in records if r["userIdentity"]["userName"].startswith("lucid-autoscaler")]
    assert len(legit) == 2
    assert all(r["sourceIPAddress"] == "autoscaling.amazonaws.com" for r in legit)
    assert all("t3.medium" in r["requestParameters"]["resourceName"] for r in legit)


def test_malicious_launches_span_two_distinct_regions():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(_artifacts(scenario))
    malicious_regions = {
        r["awsRegion"]
        for r in records
        if r["userIdentity"]["userName"].startswith("lucid-worker-role")
    }
    assert malicious_regions == {"us-east-1", "us-west-2"}
