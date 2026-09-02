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

BUNDLED_SCENARIO_FILENAMES = [
    "phishing_credential_harvest.yaml",
    "phishing_to_exfil.yaml",
    "insider_usb_exfiltration.yaml",
    "business_email_compromise.yaml",
    "sql_injection_data_breach.yaml",
    "cryptomining_cloud_compromise.yaml",
    "gcp_key_compromise.yaml",
    "aitm_session_hijack.yaml",
    "stolen_dev_credentials_aws.yaml",
    "webshell_to_dc_compromise.yaml",
    "ransomware_full_chain.yaml",
]


@pytest.fixture(params=BUNDLED_SCENARIO_FILENAMES)
def scenario_path(request) -> Path:
    """Parametrized fixture yielding the path to each bundled scenario file."""
    return SCENARIOS_DIR / request.param
