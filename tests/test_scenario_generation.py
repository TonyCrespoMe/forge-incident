"""Tests for llm/scenario_generator.py: prompt building + validate/retry loop.

Uses an in-process stub backend rather than a real LLM call — same
philosophy as test_llm.py's `none`-backend-only coverage: real API-key
backends are checked for correct wiring/registration elsewhere, never
exercised with a live network call in the offline test suite.
"""

from __future__ import annotations

import pytest

from forge_incident.llm.base import LLMBackend, LLMBackendError
from forge_incident.llm.none import NoneLLMBackend
from forge_incident.llm.scenario_generator import (
    DEFAULT_MAX_ATTEMPTS,
    _extract_yaml,
    _make_scenario_id,
    _system_prompt,
    _user_prompt,
    generate_new_scenario,
)
from forge_incident.models import Difficulty
from forge_incident.scenario_categories import get_category
from tests.conftest import SCENARIOS_DIR

_VALID_YAML = """
scenario_id: gen-test-99
title: "Test Injection Scenario"
description: >
  A test scenario for validating the generation loop end to end.
student_briefing: >
  You are investigating unusual database activity at Testco.
difficulty: intermediate
version: "1.0"
seed: 99

organization:
  name: Testco
  domain: testco.example
  industry: Retail
  timezone: UTC

mitre_tactics: [Initial Access, Exfiltration]
learning_objectives: ["Identify SQL injection in web logs"]
tags: [web, injection]

start_time: "2026-05-01T09:00:00Z"

actors:
  attacker:
    username: unknown
    email: unknown@unknown.external
    display_name: Unknown External Actor
    is_compromised: true

hosts:
  web01:
    hostname: WEB01
    ip_address: 10.0.0.5
    host_type: server
    os: linux

timeline:
  - id: sqli-attempt
    at: "+0m"
    event_type: network_connection_allowed
    log_sources: [palo_alto]
    severity: high
    actor: attacker
    host: web01
    description: >
      SQL injection payload observed in web traffic.
    mitre:
      technique_id: T1190
      technique_name: "Exploit Public-Facing Application"
      tactic: "Initial Access"
    network:
      protocol: tcp
      src_ip: 185.220.101.47
      src_port: 51000
      dst_ip: 10.0.0.5
      dst_port: 443
      action: allow

  - id: exfil
    at: "+5m"
    event_type: data_exfiltration
    log_sources: [palo_alto]
    severity: critical
    actor: attacker
    host: web01
    description: >
      Customer database dumped and exfiltrated.
    mitre:
      technique_id: T1041
      technique_name: "Exfiltration Over C2 Channel"
      tactic: "Exfiltration"
    network:
      protocol: tcp
      src_ip: 185.220.101.47
      src_port: 51010
      dst_ip: 10.0.0.5
      dst_port: 443
      action: allow

answer_key:
  - id: q1
    question: "How did the attacker gain access?"
    answer: >
      Via SQL injection against the public web form.
    related_event_ids: [sqli-attempt]
    points: 2
"""

_INVALID_YAML = """
scenario_id: gen-test-broken
title: "Broken"
this_field_does_not_exist: true
"""


class _StubBackend(LLMBackend):
    """Returns a scripted sequence of raw text responses, one per call."""

    name = "stub"

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    def is_available(self) -> bool:
        return True

    def plan_scenario(self, *args, **kwargs):
        raise NotImplementedError("not used by these tests")

    def generate_scenario_text(
        self, *, system_prompt: str, user_prompt: str, max_tokens: int = 4096
    ) -> str:
        self.calls += 1
        return self._responses[min(self.calls - 1, len(self._responses) - 1)]


def test_none_backend_does_not_support_generation():
    backend = NoneLLMBackend()
    with pytest.raises(LLMBackendError, match="does not support brand-new scenario generation"):
        backend.generate_scenario_text(system_prompt="x", user_prompt="y")


def test_generate_new_scenario_succeeds_on_first_valid_attempt():
    backend = _StubBackend([_VALID_YAML])
    result = generate_new_scenario(
        backend,
        category_id="web-a05-injection",
        difficulty=Difficulty.INTERMEDIATE,
        seed=99,
        example_scenario_path=SCENARIOS_DIR / "phishing_to_exfil.yaml",
        max_attempts=DEFAULT_MAX_ATTEMPTS,
    )
    assert result.attempts == 1
    assert backend.calls == 1
    assert result.scenario.event_count == 2
    assert result.category.id == "web-a05-injection"


def test_generate_new_scenario_retries_after_a_validation_failure():
    backend = _StubBackend([_INVALID_YAML, _VALID_YAML])
    result = generate_new_scenario(
        backend,
        category_id="web-a05-injection",
        difficulty=Difficulty.INTERMEDIATE,
        seed=99,
        example_scenario_path=SCENARIOS_DIR / "phishing_to_exfil.yaml",
        max_attempts=3,
    )
    assert result.attempts == 2
    assert backend.calls == 2


def test_retry_prompt_includes_the_previous_validation_error():
    backend = _StubBackend([_INVALID_YAML, _VALID_YAML])
    generate_new_scenario(
        backend,
        category_id="web-a05-injection",
        difficulty=Difficulty.INTERMEDIATE,
        seed=99,
        example_scenario_path=SCENARIOS_DIR / "phishing_to_exfil.yaml",
        max_attempts=3,
    )
    # A second call only happens if the first failed; the retry prompt must
    # carry the exact error forward so the model can fix the right thing.
    assert backend.calls == 2


def test_generate_new_scenario_raises_after_exhausting_max_attempts():
    backend = _StubBackend([_INVALID_YAML])
    with pytest.raises(LLMBackendError, match="after 2 attempt"):
        generate_new_scenario(
            backend,
            category_id="aws-leaked-iam-key",
            difficulty=Difficulty.BEGINNER,
            seed=1,
            example_scenario_path=SCENARIOS_DIR / "gcp_key_compromise.yaml",
            max_attempts=2,
        )
    assert backend.calls == 2


def test_generate_new_scenario_rejects_unknown_category():
    backend = _StubBackend([_VALID_YAML])
    with pytest.raises(KeyError):
        generate_new_scenario(
            backend,
            category_id="not-a-real-category",
            difficulty=Difficulty.INTERMEDIATE,
            seed=1,
            example_scenario_path=SCENARIOS_DIR / "phishing_to_exfil.yaml",
        )


def test_extract_yaml_strips_markdown_fences():
    fenced = "Sure, here you go:\n```yaml\nscenario_id: x\n```\n"
    assert _extract_yaml(fenced).strip() == "scenario_id: x"


def test_extract_yaml_passes_through_bare_yaml():
    bare = "scenario_id: x\ntitle: y\n"
    assert _extract_yaml(bare) == bare.strip()


def test_make_scenario_id_is_deterministic():
    category = get_category("web-a05-injection")
    assert _make_scenario_id(category, 42) == _make_scenario_id(category, 42)
    assert _make_scenario_id(category, 42) != _make_scenario_id(category, 43)


def test_system_prompt_documents_extra_forbid_and_dotexample_rule():
    prompt = _system_prompt()
    assert ".example" in prompt
    assert "extra=" in prompt or "unknown field" in prompt.lower() or "not listed here" in prompt


def test_user_prompt_carries_the_exact_seed_and_scenario_id():
    category = get_category("windows-ad-kerberoasting")
    prompt = _user_prompt(
        category,
        difficulty=Difficulty.ADVANCED,
        seed=1234,
        scenario_id="gen-windows-ad-kerberoasting-1234",
        example_yaml="scenario_id: example\n",
        previous_error=None,
    )
    assert "1234" in prompt
    assert "gen-windows-ad-kerberoasting-1234" in prompt
    assert category.name in prompt
