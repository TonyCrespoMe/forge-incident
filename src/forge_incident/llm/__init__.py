"""Optional LLM planning backends for natural-language scenario generation.

`get_backend(name)` is the single entry point `cli.py` uses. It never
eagerly imports a backend module until its name is actually selected — so
choosing the default `none` backend never requires ANY of the optional
third-party dependencies (`anthropic`, `httpx`, `openai`,
`google-generativeai`) to be installed. Every backend implements the same
narrow contract (see `llm.base.ScenarioPlan`): pick a bundled template,
optionally override difficulty/title/tags. None of them ever generate log
content — that's always deterministic Python in `emitters/`.
"""

from __future__ import annotations

from forge_incident.llm.base import (
    LLMBackend,
    LLMBackendError,
    ScenarioPlan,
    available_templates,
    build_scenario_from_plan,
    resolve_template_path,
)

__all__ = [
    "LLMBackend",
    "LLMBackendError",
    "ScenarioPlan",
    "available_templates",
    "build_scenario_from_plan",
    "resolve_template_path",
    "get_backend",
    "BACKEND_NAMES",
]

BACKEND_NAMES: tuple[str, ...] = ("none", "claude", "openai", "gemini", "grok", "ollama")


def get_backend(name: str) -> LLMBackend:
    """Instantiate a backend by name (one of `BACKEND_NAMES`)."""
    key = name.strip().lower()
    if key == "none":
        from forge_incident.llm.none import NoneLLMBackend

        return NoneLLMBackend()
    if key == "claude":
        from forge_incident.llm.claude import ClaudeLLMBackend

        return ClaudeLLMBackend()
    if key == "openai":
        from forge_incident.llm.openai import OpenAILLMBackend

        return OpenAILLMBackend()
    if key == "gemini":
        from forge_incident.llm.gemini import GeminiLLMBackend

        return GeminiLLMBackend()
    if key == "grok":
        from forge_incident.llm.grok import GrokLLMBackend

        return GrokLLMBackend()
    if key == "ollama":
        from forge_incident.llm.ollama import OllamaLLMBackend

        return OllamaLLMBackend()
    raise LLMBackendError(f"Unknown LLM backend {name!r}. Choose from: {BACKEND_NAMES}")
