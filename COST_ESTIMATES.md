# `generate-category` Cost Estimates

**Estimates taken: 2026-08-06.** LLM API pricing and model lineups change
frequently (see the "Aug 2026" links below — three of the four providers had
already deprecated the model this project originally defaulted to by this
date). Treat every number on this page as a snapshot, not a guarantee.
Before relying on it for budgeting, re-check current pricing at:

- Claude: <https://www.anthropic.com/pricing>
- OpenAI: <https://openai.com/api/pricing>
- Gemini: <https://ai.google.dev/gemini-api/docs/pricing>
- Grok: <https://docs.x.ai/docs/models>

## How the estimate was built

Each `generate-category` attempt sends one request with:

- **System prompt** (fixed): the full `Scenario` schema, enum values, and consistency/safety rules — measured at **9,930 characters (~2,480 tokens)**.
- **User prompt** (category-dependent, but similar size across categories): the category brief + a full bundled scenario as a few-shot format example — measured at **~14,800-14,900 characters (~3,700 tokens)** across all three difficulty levels tested.

So **input ≈ 6,200 tokens per attempt**, essentially constant regardless of category or difficulty (the difficulty guidance text itself is small; the example YAML dominates the prompt size).

**Output** scales with how many timeline events the difficulty calls for (see `llm/scenario_generator.py`'s `_DIFFICULTY_GUIDANCE`):

| Difficulty | Target events | Output budget (`max_tokens`) | Typical actual output |
|---|---|---|---|
| beginner | 8-14 | 4,096 | ~2,500 tokens |
| intermediate | 15-24 | 6,144 | ~4,000 tokens |
| advanced | 25-40 | 9,216 | ~6,500 tokens |

"Typical actual output" is an estimate scaled from the bundled example scenarios' event density, not a measurement of a real model response (this project's sandbox has no network access to make one). The output budget itself was sized with headroom on purpose: a response that gets cut off mid-YAML by hitting the token cap fails schema validation and burns a retry — costing *more* than budgeting enough tokens up front, not less.

## Pricing used (per 1M tokens, as of 2026-08-06)

| Backend | Default model (as of this date) | Input | Output |
|---|---|---|---|
| Claude | `claude-sonnet-4-5` | $3.00 | $15.00 |
| OpenAI | `gpt-4.1-mini` | $0.40 | $1.60 |
| Gemini | `gemini-2.5-flash` | $0.30 | $2.50 |
| Grok | `grok-4.3` | $1.25 | $2.50 |
| Ollama | local model | $0 (your own compute) | $0 |

## Estimated cost per successful generation

One attempt, no retries needed (the common case for a well-formed request):

| Backend | Beginner | Intermediate | Advanced |
|---|---|---|---|
| Claude | ~$0.05 | ~$0.08 | ~$0.12 |
| OpenAI | <$0.01 | ~$0.01 | ~$0.01 |
| Gemini | ~$0.01 | ~$0.01 | ~$0.02 |
| Grok | ~$0.01 | ~$0.02 | ~$0.02 |
| Ollama | $0 | $0 | $0 |

If the model's first attempt fails ForgeIncident's schema validation, `generate_new_scenario()` retries with the exact validation error fed back, up to `--max-attempts` (default 3) — multiply the relevant cell above by however many attempts it actually took. Claude is the priciest per attempt but, subjectively, the most likely to pass validation on the first try; the cheaper backends are cheaper per attempt but may need more of them.

## Known way this estimate can go stale fast

This project's `.env.example` and each `llm/*.py` backend hardcode a specific default model string (e.g. `GEMINI_MODEL=gemini-2.5-flash`). Provider model lineups turn over every few months — `gemini-2.0-flash` (this project's original Gemini default) was shut down June 1, 2026, and `grok-2-latest` (the original Grok default) was retired even earlier. If a `generate-category` call fails with a model-not-found/404-style error, that's almost certainly why: check the provider links above for the current model name and set it via `.env` (`GEMINI_MODEL=...`, `GROK_MODEL=...`, etc.) rather than assuming the hardcoded default is still current.
