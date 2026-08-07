"""Tests for the LLM planning layer, focused on the offline `none` backend
(no API key / network access needed to run these).

The API-key-based backends (claude/openai/gemini/grok) are only checked
for correct *registration* and *unavailable-without-a-key* behavior here —
actually calling out to a real LLM is out of scope for an offline test
suite, by design (see llm/base.py's Core Architecture Rule discussion)."""

from __future__ import annotations

import os

import pytest

from forge_incident.llm import BACKEND_NAMES, LLMBackendError, available_templates, build_scenario_from_plan, get_backend
from forge_incident.models import Difficulty
from tests.conftest import SCENARIOS_DIR


def test_none_backend_always_available():
    assert get_backend("none").is_available()


def test_available_templates_lists_both_bundled_scenarios():
    templates = available_templates(SCENARIOS_DIR)
    assert "phishing_to_exfil" in templates
    assert "gcp_key_compromise" in templates


def test_none_backend_matches_phishing_keywords():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "an employee clicked a phishing email attachment and malware spread to a file server",
        seed=1,
        scenarios_dir=SCENARIOS_DIR,
    )
    assert plan.scenario_template == "phishing_to_exfil"
    assert plan.backend_name == "none"
    assert plan.rationale


def test_none_backend_matches_cloud_keywords():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "a leaked GCP service account key was used to access storage buckets",
        seed=1,
        scenarios_dir=SCENARIOS_DIR,
    )
    assert plan.scenario_template == "gcp_key_compromise"


def test_none_backend_deterministic_for_same_prompt_and_seed():
    backend = get_backend("none")
    prompt = "an ambiguous prompt without strong keyword signal either way"
    p1 = backend.plan_scenario(prompt, seed=7, scenarios_dir=SCENARIOS_DIR)
    p2 = backend.plan_scenario(prompt, seed=7, scenarios_dir=SCENARIOS_DIR)
    assert p1.scenario_template == p2.scenario_template


def test_none_backend_respects_explicit_difficulty_override():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "phishing macro c2 exfiltration", seed=1, difficulty=Difficulty.ADVANCED,
        scenarios_dir=SCENARIOS_DIR,
    )
    assert plan.difficulty == Difficulty.ADVANCED


def test_none_backend_infers_difficulty_from_keywords():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "an introductory beginner-friendly phishing scenario", seed=1, scenarios_dir=SCENARIOS_DIR
    )
    assert plan.difficulty == Difficulty.BEGINNER


def test_build_scenario_from_plan_round_trips():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "phishing macro c2 lateral movement exfiltration", seed=5, scenarios_dir=SCENARIOS_DIR
    )
    scenario = build_scenario_from_plan(plan, SCENARIOS_DIR, seed=5)
    assert scenario.seed == 5
    assert scenario.scenario_id == "phishing-to-exfil-01"


def test_plan_title_and_tag_overrides_apply_without_touching_identifiers():
    backend = get_backend("none")
    plan = backend.plan_scenario(
        "phishing macro c2 exfiltration", seed=5, scenarios_dir=SCENARIOS_DIR
    )
    plan.title_override = "Custom Title"
    plan.emphasis_tags = ["custom-tag"]
    scenario = build_scenario_from_plan(plan, SCENARIOS_DIR, seed=5)
    assert scenario.title == "Custom Title"
    assert "custom-tag" in scenario.tags
    # Identifiers must be untouched by a plan — see llm/base.py's ScenarioPlan docstring.
    assert scenario.organization.domain == "globex.example"
    assert scenario.actors["victim"].email == "jsmith@globex.example"


def test_backend_names_covers_every_registered_provider():
    assert set(BACKEND_NAMES) == {"none", "claude", "openai", "gemini", "grok", "ollama"}


def test_get_backend_returns_the_right_class_for_every_name():
    from forge_incident.llm.claude import ClaudeLLMBackend
    from forge_incident.llm.gemini import GeminiLLMBackend
    from forge_incident.llm.grok import GrokLLMBackend
    from forge_incident.llm.none import NoneLLMBackend
    from forge_incident.llm.ollama import OllamaLLMBackend
    from forge_incident.llm.openai import OpenAILLMBackend

    assert isinstance(get_backend("none"), NoneLLMBackend)
    assert isinstance(get_backend("claude"), ClaudeLLMBackend)
    assert isinstance(get_backend("openai"), OpenAILLMBackend)
    assert isinstance(get_backend("gemini"), GeminiLLMBackend)
    assert isinstance(get_backend("grok"), GrokLLMBackend)
    assert isinstance(get_backend("ollama"), OllamaLLMBackend)
    # Case-insensitive, matching cli.py's --llm handling.
    assert isinstance(get_backend("CLAUDE"), ClaudeLLMBackend)


def test_get_backend_rejects_unknown_name():
    with pytest.raises(LLMBackendError):
        get_backend("not-a-real-backend")


def test_api_key_backends_report_unavailable_without_a_key():
    """None of these should need their optional dependency installed to
    correctly report is_available() == False when no key is configured —
    the key check must short-circuit before the import (see each
    backend's is_available()).
    """
    from forge_incident.llm.claude import ClaudeLLMBackend
    from forge_incident.llm.gemini import GeminiLLMBackend
    from forge_incident.llm.grok import GrokLLMBackend
    from forge_incident.llm.openai import OpenAILLMBackend

    keys_to_clear = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XAI_API_KEY", "GROK_API_KEY"]
    saved = {k: os.environ.pop(k, None) for k in keys_to_clear}
    try:
        assert ClaudeLLMBackend(api_key=None).is_available() is False
        assert OpenAILLMBackend(api_key=None).is_available() is False
        assert GeminiLLMBackend(api_key=None).is_available() is False
        assert GrokLLMBackend(api_key=None).is_available() is False
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value


def test_base_backend_generate_scenario_text_default_raises():
    """Backends that don't override generate_scenario_text (i.e. only 'none'
    relies on the base default — every API-key backend overrides it) get an
    honest LLMBackendError rather than silently doing nothing."""
    from forge_incident.llm.none import NoneLLMBackend

    with pytest.raises(LLMBackendError, match="does not support brand-new scenario generation"):
        NoneLLMBackend().generate_scenario_text(system_prompt="x", user_prompt="y")


def test_api_key_backends_override_generate_scenario_text():
    """claude/openai/gemini/grok/ollama must each define their own
    generate_scenario_text (not silently fall back to the base class's
    'unsupported' default) — generate-category requires a real backend."""
    from forge_incident.llm.claude import ClaudeLLMBackend
    from forge_incident.llm.gemini import GeminiLLMBackend
    from forge_incident.llm.grok import GrokLLMBackend
    from forge_incident.llm.ollama import OllamaLLMBackend
    from forge_incident.llm.openai import OpenAILLMBackend

    for cls in (ClaudeLLMBackend, OpenAILLMBackend, GeminiLLMBackend, GrokLLMBackend, OllamaLLMBackend):
        assert "generate_scenario_text" in cls.__dict__, f"{cls.__name__} must override generate_scenario_text"


def test_grok_backend_reads_either_xai_or_grok_api_key_env_var():
    from forge_incident.llm.grok import GrokLLMBackend

    saved = {k: os.environ.pop(k, None) for k in ("XAI_API_KEY", "GROK_API_KEY")}
    try:
        os.environ["GROK_API_KEY"] = "test-key-via-grok-alias"
        assert GrokLLMBackend().api_key == "test-key-via-grok-alias"
    finally:
        os.environ.pop("GROK_API_KEY", None)
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
