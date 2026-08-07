"""Google Gemini planning backend — optional.

Install with:   pip install "forge-incident[gemini]"
Configure with: GEMINI_API_KEY (required) and GEMINI_MODEL (optional) in
                .env — see .env.example. Get a key at https://aistudio.google.com/apikey

Per the Core Architecture Rule, this backend is only ever asked to choose
among the *existing* bundled scenario templates and set a few cosmetic
fields (see `llm.base.ScenarioPlan`) — never to invent timestamps, hosts,
IPs, hashes, or log content. A Gemini-planned package is exactly as
deterministic and reproducible from its seed as a plain `--from-yaml` run.

Uses the `google-generativeai` SDK. Google's Gemini model lineup moves
fast; if `GEMINI_MODEL`'s default below 404s for you, check
https://ai.google.dev/gemini-api/docs/models and set GEMINI_MODEL in .env.
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

__all__ = ["GeminiLLMBackend"]

_DEFAULT_MODEL = "gemini-2.0-flash"

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


class GeminiLLMBackend(LLMBackend):
    name = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", _DEFAULT_MODEL)

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import google.generativeai  # noqa: F401
        except ImportError:
            return False
        return True

    def plan_scenario(
        self,
        prompt: str,
        *,
        seed: int,
        difficulty: Difficulty | None = None,
        scenarios_dir: str | Path = "scenarios",
    ) -> ScenarioPlan:
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise LLMBackendError(
                "The 'gemini' backend requires the google-generativeai package. Install it "
                'with: pip install "forge-incident[gemini]"  (or pass --llm none / --llm claude)'
            ) from exc

        if not self.api_key:
            raise LLMBackendError(
                "GEMINI_API_KEY is not set. Add it to your .env (see .env.example), or "
                "pass --llm none to generate fully offline."
            )

        templates = available_templates(scenarios_dir)
        if not templates:
            raise LLMBackendError(f"No scenario templates found under {scenarios_dir}")

        user_prompt = (
            f"Available templates: {templates}\n"
            f"Requested difficulty override (may be null): "
            f"{difficulty.value if difficulty else 'null'}\n"
            f"Instructor's natural-language request:\n{prompt}\n"
        )

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_name=self.model,
            system_instruction=_SYSTEM_PROMPT,
            generation_config={"response_mime_type": "application/json"},
        )
        try:
            response = model.generate_content(user_prompt)
        except Exception as exc:  # google-generativeai raises its own exception hierarchy
            raise LLMBackendError(f"Gemini API call failed: {exc}") from exc

        text = getattr(response, "text", "") or ""
        payload = extract_json_object(text)

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise LLMBackendError(f"Gemini did not return valid JSON:\n{text}") from exc

        template = data.get("scenario_template")
        if template not in templates:
            raise LLMBackendError(
                f"Gemini chose template {template!r}, which is not one of the available "
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

    def generate_scenario_text(self, *, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise LLMBackendError(
                "The 'gemini' backend requires the google-generativeai package. Install it "
                'with: pip install "forge-incident[gemini]"'
            ) from exc

        if not self.api_key:
            raise LLMBackendError("GEMINI_API_KEY is not set. Add it to your .env (see .env.example).")

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_name=self.model,
            system_instruction=system_prompt,
            generation_config={"max_output_tokens": max_tokens},
        )
        try:
            response = model.generate_content(user_prompt)
        except Exception as exc:
            raise LLMBackendError(f"Gemini API call failed: {exc}") from exc

        return getattr(response, "text", "") or ""
