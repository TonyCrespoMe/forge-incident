"""Tests for packager.py: student/instructor separation and reproducibility."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone

from forge_incident.packager import build_packages
from forge_incident.scenario_loader import load_scenario
from tests.conftest import SCENARIOS_DIR

_FIXED_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_student_zip_has_no_instructor_material(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    result = build_packages(
        scenario, tmp_path, source_path=SCENARIOS_DIR / "phishing_to_exfil.yaml"
    )
    with zipfile.ZipFile(result.student_zip) as zf:
        names = zf.namelist()
    assert "README.md" in names
    assert not any(n.startswith("instructor/") for n in names)
    assert any(n.startswith("logs/") for n in names)


def test_instructor_zip_has_answer_key_guide_and_manifest(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    result = build_packages(
        scenario, tmp_path, source_path=SCENARIOS_DIR / "phishing_to_exfil.yaml"
    )
    with zipfile.ZipFile(result.instructor_zip) as zf:
        names = zf.namelist()
        manifest = json.loads(zf.read("instructor/manifest.json"))

    for expected in (
        "instructor/INSTRUCTOR_GUIDE.md",
        "instructor/ANSWER_KEY.md",
        "instructor/manifest.json",
        "instructor/scenario_source.yaml",
    ):
        assert expected in names

    assert manifest["scenario_id"] == scenario.scenario_id
    assert len(manifest["timeline"]) == scenario.event_count
    assert len(manifest["answer_key"]) == len(scenario.answer_key)


def test_student_readme_has_no_answer_key_or_mitre_ids(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    result = build_packages(scenario, tmp_path)
    with zipfile.ZipFile(result.student_zip) as zf:
        readme = zf.read("README.md").decode()

    for event in scenario.timeline:
        if event.mitre:
            assert event.mitre.technique_id not in readme
    for item in scenario.answer_key:
        assert item.answer.strip()[:20] not in readme


def test_student_zip_byte_identical_across_runs(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    r1 = build_packages(scenario, tmp_path / "run1")
    r2 = build_packages(scenario, tmp_path / "run2")
    assert r1.student_zip.read_bytes() == r2.student_zip.read_bytes()


def test_instructor_zip_byte_identical_with_fixed_generated_at(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    r1 = build_packages(scenario, tmp_path / "run1", generated_at=_FIXED_TIME)
    r2 = build_packages(scenario, tmp_path / "run2", generated_at=_FIXED_TIME)
    assert r1.instructor_zip.read_bytes() == r2.instructor_zip.read_bytes()


def test_llm_generated_flag_appears_in_instructor_package_only(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    result = build_packages(
        scenario,
        tmp_path,
        llm_generated_by="claude",
        generation_warnings=["example warning"],
    )
    with zipfile.ZipFile(result.instructor_zip) as zf:
        guide = zf.read("instructor/INSTRUCTOR_GUIDE.md").decode()
        manifest = json.loads(zf.read("instructor/manifest.json"))
    with zipfile.ZipFile(result.student_zip) as zf:
        student_readme = zf.read("README.md").decode()

    assert "LLM-generated scenario" in guide
    assert "claude" in guide
    assert "example warning" in guide
    assert manifest["llm_generated_by"] == "claude"
    assert manifest["generation_warnings"] == ["example warning"]
    assert manifest["requires_instructor_review"] is True
    assert "LLM-generated" not in student_readme
    assert "claude" not in student_readme


def test_hand_authored_package_has_no_llm_generated_flag(tmp_path):
    scenario = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml")
    result = build_packages(scenario, tmp_path)
    with zipfile.ZipFile(result.instructor_zip) as zf:
        guide = zf.read("instructor/INSTRUCTOR_GUIDE.md").decode()
        manifest = json.loads(zf.read("instructor/manifest.json"))
    assert "LLM-generated scenario" not in guide
    assert manifest["llm_generated_by"] is None
    assert manifest["requires_instructor_review"] is False


def test_different_seeds_produce_different_filenames(tmp_path):
    a = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml", seed=1)
    b = load_scenario(SCENARIOS_DIR / "phishing_to_exfil.yaml", seed=2)
    ra = build_packages(a, tmp_path)
    rb = build_packages(b, tmp_path)
    assert ra.student_zip != rb.student_zip
    assert ra.student_zip.exists() and rb.student_zip.exists()
