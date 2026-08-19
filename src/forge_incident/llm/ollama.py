"""Ollama (local LLM) planning backend — optional.

Install with:   pip install "forge-incident[ollama]"
Configure with: OLLAMA_HOST (default http://localhost:11434) and
                OLLAMA_MODEL (default llama3.1) in .env — see .env.example.
Requires a running `ollama serve` with the model already pulled.

Like the Claude backend, Ollama is only ever asked to choose a scenario
template and set a few cosmetic fields (see `llm.base.ScenarioPlan`) —
never to invent log content — so a locally-planned package is exactly as
deterministic as any other. This backend is what lets ForgeIncident do
natural-language planning with zero external network dependency, using
whatever model the instructor already has pulled locally.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from forge_incident.llm.base import (
    LLMBackend,
    LLMBackendError,
    ScenarioPlan,
    available_templates,
    extract_json_object,
)
from forge_incident.models import Difficulty

__all__ = ["OllamaLLMBackend"]

_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "llama3.1"

_SYSTEM_PROMPT = """You are the scenario-planning module of ForgeIncident, an \
offline DFIR/purple-team training-package generator. You never invent \
timestamps, IP addresses, hashes, hostnames, or log content — you only \
choose among already-built scenario templates and set a few cosmetic \
fields. Respond with ONLY a single JSON object — no prose, no markdown \
fences — matching exactly this shape:

{"scenario_template": "<one of the available template names, verbatim>",
 "difficulty": "beginner" | "intermediate" | "advanced" | null,
 "title_override": "<short title reframing the request, or null>",
 "emphasis_tags": ["<lowercase tag>", ...],
 "rationale": "<one or two sentences explaining your choice>"}
"""


class OllamaLLMBackend(LLMBackend):
    name = "ollama"

    def __init__(self, host: str | None = None, model: str | None = None) -> None:
        self.host = (host or os.environ.get("OLLAMA_HOST", _DEFAULT_HOST)).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", _DEFAULT_MODEL)

    def is_available(self) -> bool:
        try:
            import httpx
        except ImportError:
            return False
        try:
            resp = httpx.get(f"{self.host}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def plan_scenario(
        self,
        prompt: str,
        *,
        seed: int,
        difficulty: Difficulty | None = None,
        scenarios_dir: str | Path = "scenarios",
    ) -> ScenarioPlan:
        try:
            import httpx
        except ImportError as exc:
            raise LLMBackendError(
                "The 'ollama' backend requires the httpx package. Install it with: "
                'pip install "forge-incident[ollama]"  (or pass --llm none / --llm claude)'
            ) from exc

        templates = available_templates(scenarios_dir)
        if not templates:
            raise LLMBackendError(f"No scenario templates found under {scenarios_dir}")

        user_prompt = (
            f"Available templates: {templates}\n"
            f"Requested difficulty override (may be null): "
            f"{difficulty.value if difficulty else 'null'}\n"
            f"Instructor's natural-language request:\n{prompt}\n"
        )

        try:
            resp = httpx.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "format": "json",
                },
                timeout=60.0,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise LLMBackendError(
                f"Could not reach Ollama at {self.host} (is `ollama serve` running, and is "
                f"'{self.model}' pulled? try: ollama pull {self.model}): {exc}"
            ) from exc

        try:
            body = resp.json()
            text = body["message"]["content"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LLMBackendError(f"Unexpected response shape from Ollama: {resp.text}") from exc

        payload = extract_json_object(text)
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise LLMBackendError(f"Ollama did not return valid JSON:\n{text}") from exc

        template = data.get("scenario_template")
        if template not in templates:
            raise LLMBackendError(
                f"Ollama chose template {template!r}, which is not one of the available "
                f"templates {templates}."
            )

        plan_difficulty = difficulty
        if plan_difficulty is None and data.get("difficulty"):
            try:
                plan_difficulty = Difficulty(data["difficulty"])
            except ValueError:
                plan_difficulty = None

        return ScenarioPlan(
            scenario_template=template,
            difficulty=plan_difficulty,
            title_override=data.get("title_override") or None,
            emphasis_tags=[str(t) for t in (data.get("emphasis_tags") or [])],
            original_prompt=prompt,
            rationale=str(data.get("rationale", "")),
            backend_name=self.name,
        )

    def generate_scenario_text(
        self, *, system_prompt: str, user_prompt: str, max_tokens: int = 4096
    ) -> str:
        try:
            import httpx
        except ImportError as exc:
            raise LLMBackendError(
                "The 'ollama' backend requires the httpx package. Install it with: "
                'pip install "forge-incident[ollama]"'
            ) from exc

        try:
            resp = httpx.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "options": {"num_predict": max_tokens},
                },
                timeout=180.0,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise LLMBackendError(
                f"Could not reach Ollama at {self.host} (is `ollama serve` running, and is "
                f"'{self.model}' pulled?): {exc}"
            ) from exc

        try:
            body = resp.json()
            return body["message"]["content"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LLMBackendError(f"Unexpected response shape from Ollama: {resp.text}") from exc
