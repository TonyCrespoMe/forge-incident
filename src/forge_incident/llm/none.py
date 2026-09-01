"""Deterministic, fully offline LLM backend — ForgeIncident's default.

`NoneLLMBackend` is what makes "must work fully offline" literally true:
no network access, no API key, no third-party dependency beyond the
standard library. It doesn't generate free text at all; it maps a
natural-language prompt to the closest bundled scenario template using
transparent keyword scoring, so its choice is always explainable in the
`rationale` field and always reproducible for a given prompt + seed.
"""

from __future__ import annotations

from pathlib import Path

from forge_incident.llm.base import LLMBackend, ScenarioPlan, available_templates
from forge_incident.models import Difficulty
from forge_incident.scenario_loader import derive_rng

__all__ = ["NoneLLMBackend"]

# Keyword -> template mapping. This backend's entire "understanding" of a
# prompt is "does it contain these substrings" — deliberately simple and
# inspectable, which is exactly why it never needs a network connection.
# Add an entry here whenever a new scenario template is added.
_TEMPLATE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "phishing_to_exfil": (
        "phish",
        "email",
        "attachment",
        "macro",
        "spreadsheet",
        "excel",
        "invoice",
        "malware",
        "endpoint",
        "workstation",
        "powershell",
        "c2",
        "command and control",
        "lateral movement",
        "file server",
        "ransomware",
        "spearphish",
    ),
    "gcp_key_compromise": (
        "cloud",
        "gcp",
        "google cloud",
        "aws",
        "azure",
        "s3",
        "bucket",
        "service account",
        "iam",
        "credential leak",
        "leaked key",
        "leaked credential",
        "api key",
        "devops",
        "ci/cd",
        "storage",
        "saas",
        "identity and access",
    ),
}

# Used only when no template's keywords match the prompt at all.
_DEFAULT_TEMPLATE = "phishing_to_exfil"

_DIFFICULTY_KEYWORDS: dict[Difficulty, tuple[str, ...]] = {
    Difficulty.BEGINNER: ("beginner", "intro", "introductory", "easy", "101", "first scenario"),
    # Checked before ADVANCED so an explicitly "expert" prompt isn't swallowed
    # by the broader advanced keyword set (dict order is insertion order).
    Difficulty.EXPERT: ("expert", "hardest", "nation-state", "apt", "red team", "multi-day"),
    Difficulty.ADVANCED: ("advanced", "hard", "sophisticated", "targeted"),
}


class NoneLLMBackend(LLMBackend):
    name = "none"

    def is_available(self) -> bool:
        return True

    def plan_scenario(
        self,
        prompt: str,
        *,
        seed: int,
        difficulty: Difficulty | None = None,
        scenarios_dir: str | Path = "scenarios",
    ) -> ScenarioPlan:
        text = prompt.lower()
        present = set(available_templates(scenarios_dir))

        scores: dict[str, int] = {}
        matched_keywords: dict[str, list[str]] = {}
        for template, keywords in _TEMPLATE_KEYWORDS.items():
            if present and template not in present:
                continue  # template isn't actually on disk; can't choose it
            hits = [kw for kw in keywords if kw in text]
            if hits:
                scores[template] = len(hits)
                matched_keywords[template] = hits

        if scores:
            best_score = max(scores.values())
            tied = sorted(t for t, s in scores.items() if s == best_score)
            if len(tied) == 1:
                chosen = tied[0]
            else:
                # Deterministic tie-break driven by the seed (not simply
                # alphabetical), so an ambiguous prompt can still explore
                # different, equally-valid templates across --seed values.
                rng = derive_rng(seed, "none_backend", "template_tiebreak", text)
                chosen = tied[rng.randrange(len(tied))]
            rationale = (
                f"Matched keywords {matched_keywords[chosen]} to template {chosen!r} "
                f"(score {best_score})."
            )
            if len(tied) > 1:
                rationale += f" Tied with {tied}; tie broken deterministically from the seed."
        else:
            fallback_pool = sorted(present) if present else list(_TEMPLATE_KEYWORDS)
            chosen = _DEFAULT_TEMPLATE if _DEFAULT_TEMPLATE in fallback_pool else fallback_pool[0]
            rationale = (
                "No scenario keywords matched the prompt; falling back to the default "
                f"template {chosen!r}. Available templates: {fallback_pool}."
            )

        resolved_difficulty = difficulty
        if resolved_difficulty is None:
            for level, keywords in _DIFFICULTY_KEYWORDS.items():
                hits = [kw for kw in keywords if kw in text]
                if hits:
                    resolved_difficulty = level
                    rationale += f" Difficulty inferred as {level.value!r} from {hits}."
                    break

        return ScenarioPlan(
            scenario_template=chosen,
            difficulty=resolved_difficulty,
            title_override=None,
            emphasis_tags=[],
            original_prompt=prompt,
            rationale=rationale,
            backend_name=self.name,
        )
