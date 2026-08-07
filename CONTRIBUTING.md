# Contributing to ForgeIncident

## Setup

Follow [GETTING_STARTED.md](GETTING_STARTED.md) §§1-3 to get a working `.venv`, or the short version:

```bash
git clone <this repo>
cd forge-incident
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
pytest              # full test suite must pass
ruff check src tests   # linting must pass
```

Both run automatically on every push/PR via GitHub Actions (`.github/workflows/tests.yml`) across Python 3.10-3.12 — a PR with a red check won't be merged.

## What's easy to contribute

- **A new scenario category's few-shot handling** or a fix to an existing category's premise/MITRE mapping in `src/forge_incident/scenario_categories.py` — see [SCENARIO_CATEGORY_TAXONOMY.md](SCENARIO_CATEGORY_TAXONOMY.md) for sourcing conventions.
- **A new emitter** (e.g. a native macOS Unified Log format, Kubernetes audit logs, a real Sysmon-config-aware Windows variant) — see `src/forge_incident/emitters/base.py`'s docstring and any existing emitter for the pattern; register it in `emitters/__init__.py`'s `ALL_EMITTERS`.
- **A new hand-written scenario YAML** under `scenarios/` — see the "Writing your own scenario" section of [README.md](README.md).
- Bug reports and small fixes, obviously.

## What needs more discussion first

Anything touching `models.py` (the shared schema every emitter and the LLM generation prompt depend on), the Core Architecture Rule described in `llm/base.py` (deterministic log content, LLM used only for planning/generation *inputs*, never for touching identifiers directly), or the student/instructor content-separation boundary in `packager.py`. Open an issue before a large PR in these areas.

## Reporting a security/content issue

If an LLM-generated scenario (`generate-category`) produced content that shouldn't have passed the safety rules in `llm/scenario_generator.py` (e.g. functional exploit code, a real-looking non-fictional entity), please open an issue with the category, seed, and backend used so the prompt can be tightened.
