"""Shared pytest fixtures.

Assumes an editable install (`pip install -e ".[dev]"`) so `forge_incident`
is importable without path hacks — the same assumption every other module
in this project makes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = REPO_ROOT / "scenarios"

BUNDLED_SCENARIO_FILENAMES = ["phishing_to_exfil.yaml", "gcp_key_compromise.yaml"]


@pytest.fixture(params=BUNDLED_SCENARIO_FILENAMES)
def scenario_path(request) -> Path:
    """Parametrized fixture yielding the path to each bundled scenario file."""
    return SCENARIOS_DIR / request.param
