"""xAI Grok planning backend — optional.

Install with:   pip install "forge-incident[grok]"
Configure with: XAI_API_KEY (required) and GROK_MODEL (optional) in .env
                — see .env.example. Get a key at https://console.x.ai

Per the Core Architecture Rule, this backend is only ever asked to choose
among the *existing* bundled scenario templates and set a few cosmetic
fields (see `llm.base.ScenarioPlan`) — never to invent timestamps, hosts,
IPs, hashes, or log content. A Grok-planned package is exactly as
deterministic and reproducible from its seed as a plain `--from-yaml` run.

xAI's API is intentionally OpenAI-compatible, so this backend just points
the `openai` SDK at xAI's base URL rather than pulling in a separate
client library. The default below (grok-4.3, current flagship-tier as of
Aug 2026) is xAI's cheaper flagship rather than the newest grok-4.5, since
this project favors keeping default per-run cost low. If `GROK_MODEL`'s
default is no longer current, check https://docs.x.ai/docs/models and set
GROK_MODEL in .env.
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

__all__ = ["GrokLLMBackend"]

_DEFAULT_MODEL = "grok-4.3"
_XAI_BASE_URL = "https://api.x.ai/v1"

_SYSTEM_PROMPT = """You are the scenario-planning module of ForgeIncident, an \
offline DFIR/purple-team training-package generator. You never invent \
timestamps, IP addresses, hashes, hostnames, or log content — you only \
choose among already-built scenario templates and set a few cosmetic \
fields. Respond with a single JSON object and nothing else, matching \
exactly this shape:

{"scenario_template": "<one of the available template names, verbatim>",
 "difficulty": "beginner" | "intermediate" | "advanced" | null,
 "title_override": "<short title reframing the request, or null>",
 "emphasis_tags": ["<lowercase tag>", ...],
 "rationale": "<one or two sentences explaining your choice>"}
"""


class GrokLLMBackend(LLMBackend):
    name = "grok"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
        self.model = model or os.environ.get("GROK_MODEL", _DEFAULT_MODEL)

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import openai  # noqa: F401  (xAI is OpenAI-SDK-compatible)
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
            import openai
        except ImportError as exc:
            raise LLMBackendError(
                "The 'grok' backend requires the openai package (xAI's API is OpenAI-SDK-"
                'compatible). Install it with: pip install "forge-incident[grok]"  '
                "(or pass --llm none / --llm claude)"
            ) from exc

        if not self.api_key:
            raise LLMBackendError(
                "XAI_API_KEY is not set. Add it to your .env (see .env.example), or "
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

        client = openai.OpenAI(api_key=self.api_key, base_url=_XAI_BASE_URL)
        try:
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=512,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except Exception as exc:
            raise LLMBackendError(f"Grok API call failed: {exc}") from exc

        text = response.choices[0].message.content or ""
        payload = extract_json_object(text)

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise LLMBackendError(f"Grok did not return valid JSON:\n{text}") from exc

        template = data.get("scenario_template")
        if template not in templates:
            raise LLMBackendError(
                f"Grok chose template {template!r}, which is not one of the available "
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
            import openai
        except ImportError as exc:
            raise LLMBackendError(
                "The 'grok' backend requires the openai package (xAI's API is OpenAI-SDK-"
                'compatible). Install it with: pip install "forge-incident[grok]"'
            ) from exc

        if not self.api_key:
            raise LLMBackendError("XAI_API_KEY is not set. Add it to your .env (see .env.example).")

        client = openai.OpenAI(api_key=self.api_key, base_url=_XAI_BASE_URL)
        try:
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except Exception as exc:
            raise LLMBackendError(f"Grok API call failed: {exc}") from exc

        return response.choices[0].message.content or ""
