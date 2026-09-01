"""Tests for the Okta session-ID correlation mechanic and the bundled
aitm_session_hijack.yaml scenario built on it.

This scenario's entire teaching point is structural rather than
line-by-line: the proof of session theft is that one externalSessionId
value appears from more than one IP with no fresh account_login_success
event between the appearances. If a future change to the Okta emitter
silently dropped the `extra["session_id"]` override (falling back to the
per-event derived ID for every record), this scenario would quietly stop
proving anything -- it would still "load" and still "render", just without
its central mechanic. These tests pin that mechanic directly.
"""

from __future__ import annotations

import json

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.scenario_loader import load_scenario, load_scenario_from_text
from tests.conftest import SCENARIOS_DIR

SCENARIO_FILE = SCENARIOS_DIR / "aitm_session_hijack.yaml"

_STOLEN_SESSION = "102u9F21kLQpZmR8x3Vt7c"
_PROXY_IP = "192.0.2.90"
_ATTACKER_IP = "192.0.2.140"
_VICTIM_IP = "198.51.100.212"


def _okta_records(scenario) -> list[dict]:
    artifacts = run_all(scenario, BUILTIN_EMITTERS)
    okta_content = next(a.content for a in artifacts if "/okta/" in a.relative_path)
    return [json.loads(line) for line in okta_content.strip().splitlines()]


# --------------------------------------------------------------------------
# The emitter mechanic, in isolation
# --------------------------------------------------------------------------

_SESSION_OVERRIDE_YAML = """
scenario_id: session-override-test
title: "Session ID override test"
description: >
  Instructor narrative that must never appear in any rendered log.
student_briefing: >
  Investigate.
difficulty: beginner
seed: 11
organization:
  name: Testco
  domain: testco.example
start_time: "2026-01-01T09:00:00Z"
actors:
  victim:
    username: jdoe
    email: jdoe@testco.example
    display_name: Jane Doe
timeline:
  - id: first
    at: "+0m"
    event_type: account_login_success
    log_sources: [okta]
    severity: high
    actor: victim
    description: First use of the shared session.
    network:
      protocol: tcp
      src_ip: 203.0.113.10
      src_port: 1000
      dst_ip: 203.0.113.1
      dst_port: 443
      action: allow
    extra:
      session_id: "shared-token-xyz"
  - id: second
    at: "+5m"
    event_type: session_token_replay
    log_sources: [okta]
    severity: critical
    actor: victim
    description: Second use, different IP, same token.
    network:
      protocol: tcp
      src_ip: 203.0.113.20
      src_port: 2000
      dst_ip: 203.0.113.1
      dst_port: 443
      action: allow
    extra:
      session_id: "shared-token-xyz"
  - id: unrelated
    at: "+10m"
    event_type: account_login_success
    log_sources: [okta]
    severity: info
    actor: victim
    description: An ordinary, unrelated sign-in with no override.
    network:
      protocol: tcp
      src_ip: 203.0.113.10
      src_port: 3000
      dst_ip: 203.0.113.1
      dst_port: 443
      action: allow
"""


def test_okta_session_id_override_is_shared_across_events():
    scenario = load_scenario_from_text(_SESSION_OVERRIDE_YAML, seed=11)
    records = _okta_records(scenario)
    assert len(records) == 3
    first, second, unrelated = records
    assert first["authenticationContext"]["externalSessionId"] == "shared-token-xyz"
    assert second["authenticationContext"]["externalSessionId"] == "shared-token-xyz"
    assert first["client"]["ipAddress"] != second["client"]["ipAddress"]


def test_okta_session_id_defaults_to_a_per_event_value_without_override():
    scenario = load_scenario_from_text(_SESSION_OVERRIDE_YAML, seed=11)
    records = _okta_records(scenario)
    unrelated = records[2]
    assert unrelated["authenticationContext"]["externalSessionId"] != "shared-token-xyz"
    # And it must still be unique per event -- not just a different constant.
    ids = {r["authenticationContext"]["externalSessionId"] for r in records}
    assert len(ids) == 2  # the two overridden events collapse to one shared ID


def test_session_token_replay_maps_to_a_real_okta_event_type():
    scenario = load_scenario_from_text(_SESSION_OVERRIDE_YAML, seed=11)
    records = _okta_records(scenario)
    assert records[1]["eventType"].startswith(("user.", "system.", "group.", "security."))
    assert records[1]["outcome"]["result"] == "SUCCESS"


# --------------------------------------------------------------------------
# The bundled scenario
# --------------------------------------------------------------------------


def test_scenario_loads():
    scenario = load_scenario(SCENARIO_FILE)
    assert scenario.scenario_id == "aitm-session-hijack-01"


def test_the_stolen_session_id_appears_from_more_than_one_ip():
    scenario = load_scenario(SCENARIO_FILE)
    records = _okta_records(scenario)
    stolen = [r for r in records if r["authenticationContext"]["externalSessionId"] == _STOLEN_SESSION]
    assert len(stolen) >= 3, "the stolen session should recur across multiple log lines"
    ips = {r["client"]["ipAddress"] for r in stolen}
    assert _PROXY_IP in ips
    assert _ATTACKER_IP in ips
    assert len(ips) >= 2, "the whole point is the same session moving to a new IP"


def test_no_fresh_signin_sits_between_the_first_theft_and_its_reuse():
    """The structural proof this scenario is built on: once the stolen
    session first appears, every subsequent use of that SAME session ID
    must not be preceded, anywhere later in the log, by a fresh
    account_login_success on a *different* session ID from the attacker's
    IP. In other words: the attacker is never seen re-authenticating --
    only reusing."""
    scenario = load_scenario(SCENARIO_FILE)
    records = _okta_records(scenario)

    first_theft_index = next(
        i
        for i, r in enumerate(records)
        if r["authenticationContext"]["externalSessionId"] == _STOLEN_SESSION
    )
    later_records = records[first_theft_index + 1 :]
    attacker_signins = [
        r
        for r in later_records
        if r["eventType"] == "user.session.start" and r["client"]["ipAddress"] == _ATTACKER_IP
    ]
    assert not attacker_signins, (
        "the attacker's IP must never appear on a fresh account_login_success -- "
        "every attacker touchpoint after the theft is a reuse, not a new sign-in"
    )


def test_victim_own_sessions_never_share_the_stolen_id():
    scenario = load_scenario(SCENARIO_FILE)
    records = _okta_records(scenario)
    victim_records = [r for r in records if r["client"]["ipAddress"] == _VICTIM_IP]
    assert victim_records, "expected at least one record from the victim's real IP"
    for r in victim_records:
        assert r["authenticationContext"]["externalSessionId"] != _STOLEN_SESSION


def test_two_device_registrations_are_distinguishable_only_by_session():
    """Both registration events use the same eventType (they're the same
    *kind* of action); the malicious one is identifiable only because it
    carries the stolen session ID and the attacker's IP. If this test ever
    fails because the two events became distinguishable some OTHER way
    (e.g. a different eventType), the scenario's central lesson --
    "the action looks identical, only the context differs" -- has been
    lost."""
    scenario = load_scenario(SCENARIO_FILE)
    records = _okta_records(scenario)
    registrations = [r for r in records if r["eventType"] == "user.mfa.factor.activate"]
    assert len(registrations) == 2
    assert registrations[0]["eventType"] == registrations[1]["eventType"]

    benign, malicious = registrations
    assert benign["client"]["ipAddress"] == _VICTIM_IP
    assert benign["authenticationContext"]["externalSessionId"] != _STOLEN_SESSION
    assert malicious["client"]["ipAddress"] == _ATTACKER_IP
    assert malicious["authenticationContext"]["externalSessionId"] == _STOLEN_SESSION


def test_scenario_produces_no_failed_signin_anywhere():
    """The scenario's premise: MFA was satisfied correctly throughout, so
    unlike every other identity-based scenario in this catalog, there is
    no account_login_failure event to notice at all."""
    scenario = load_scenario(SCENARIO_FILE)
    records = _okta_records(scenario)
    assert all(r["outcome"]["result"] == "SUCCESS" for r in records)
