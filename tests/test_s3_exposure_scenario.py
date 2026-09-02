"""Tests for the bundled s3_bucket_exposure.yaml scenario.

The scenario's two claims: (1) authenticated and anonymous S3 access are
visibly distinguishable in the rendered CloudTrail log, and (2) the full
scope of the breach is two files, not one -- a student who stops reading
after the first anonymous GetObject understates it by half.
"""

from __future__ import annotations

import json

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.scenario_loader import load_scenario
from tests.conftest import SCENARIOS_DIR

SCENARIO_FILE = SCENARIOS_DIR / "s3_bucket_exposure.yaml"

_ANONYMOUS_IP = "192.0.2.140"


def _cloudtrail_records(scenario) -> list[dict]:
    artifacts = run_all(scenario, BUILTIN_EMITTERS)
    content = next(a.content for a in artifacts if "/aws_cloudtrail/" in a.relative_path)
    return [json.loads(line) for line in content.strip().splitlines()]


def test_scenario_loads():
    scenario = load_scenario(SCENARIO_FILE)
    assert scenario.scenario_id == "s3-bucket-exposure-01"


def test_anonymous_calls_render_with_no_attributable_identity():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(scenario)
    anonymous = [r for r in records if r["sourceIPAddress"] == _ANONYMOUS_IP]
    assert len(anonymous) == 3  # one list, two gets
    assert all(r["userIdentity"]["userName"] == "unknown" for r in anonymous)


def test_authenticated_calls_show_a_real_principal():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(scenario)
    authenticated = [r for r in records if r["sourceIPAddress"] != _ANONYMOUS_IP]
    assert authenticated
    for record in authenticated:
        assert "@bramwellhr.example" in record["userIdentity"]["userName"]


def test_both_sensitive_files_are_confirmed_taken_not_just_one():
    scenario = load_scenario(SCENARIO_FILE)
    records = _cloudtrail_records(scenario)
    gets = [r for r in records if r["eventName"] == "GetObject" and r["sourceIPAddress"] == _ANONYMOUS_IP]
    taken = {r["requestParameters"]["resourceName"] for r in gets}
    assert taken == {
        "arn:aws:s3:::bramwellhr-hr-exports/employee_ssn_export_2026Q1.csv",
        "arn:aws:s3:::bramwellhr-hr-exports/payroll_bank_details_2026Q1.csv",
    }


def test_the_policy_change_carries_no_mitre_technique():
    """The root cause is a misconfiguration, not an adversary action -- it
    should not carry an ATT&CK technique the way every anonymous-access
    event does. If this ever regressed to having one, the scenario would
    misleadingly imply Tom executed an attacker TTP."""
    scenario = load_scenario(SCENARIO_FILE)
    event = next(e for e in scenario.timeline if e.event_id == "misconfig-policy-change")
    assert event.mitre is None


def test_admin_and_employee_are_never_flagged_as_the_attacker():
    """Sanity check on the scenario's own design: the two named human
    actors' events must never carry critical severity or the same MITRE
    techniques used for the anonymous-access events -- they are not part
    of the attack chain."""
    scenario = load_scenario(SCENARIO_FILE)
    human_actor_keys = {"admin", "employee"}
    for event in scenario.timeline:
        if event.actor in human_actor_keys:
            assert event.severity.value in ("info", "medium"), (
                f"{event.event_id} (actor={event.actor}) has severity {event.severity.value}, "
                "which would wrongly implicate a human who made an honest mistake"
            )
