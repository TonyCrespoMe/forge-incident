"""Invariants the bundled scenario catalog must hold as it grows.

These are curriculum-level tests rather than per-scenario ones. The catalog
is meant to be a teaching progression (see SCENARIO_CURRICULUM.md), and
these pin the properties that make it one — so adding a scenario that
breaks the progression fails loudly instead of quietly degrading it.
"""

from __future__ import annotations

from forge_incident.models import Difficulty
from forge_incident.scenario_loader import load_scenario
from forge_incident.scoring import default_is_opportunity
from tests.conftest import BUNDLED_SCENARIO_FILENAMES, SCENARIOS_DIR

# Difficulty tiers where a scenario MUST contain benign activity. Below
# intermediate it's optional; from intermediate up, a scenario with no
# benign events can't exercise false-positive scoring and teaches students
# that everything unusual is an attack.
_TIERS_REQUIRING_BENIGN = {
    Difficulty.INTERMEDIATE,
    Difficulty.ADVANCED,
    Difficulty.EXPERT,
}

# Sanity floors, NOT a rubric. `models.Difficulty` defines difficulty as
# analytical load, not event count -- gcp_key_compromise is only 9 events but
# teaches a genuinely subtle lesson (cloud logs identify the credential, never
# the human), and forcing it to 20 events to satisfy a number would make it
# worse, not harder. These floors exist only to catch a scenario that claims a
# tier it obviously cannot support.
_MIN_EVENTS = {
    Difficulty.BEGINNER: 6,
    Difficulty.INTERMEDIATE: 8,
    Difficulty.ADVANCED: 9,
    Difficulty.EXPERT: 25,
}

# Human identities must sit on the RFC 2606 reserved TLD. Machine and service
# identities are exempt because their address format is dictated by the cloud
# provider, and faking it would teach students the wrong shape -- a GCP service
# account really does look like name@project.iam.gserviceaccount.com, and a
# scenario that wrote name@project.example would be unrealistic.
_SERVICE_IDENTITY_SUFFIXES = (
    ".iam.gserviceaccount.com",   # GCP service accounts
    ".amazonaws.com",             # AWS service principals
)


def _all_scenarios():
    return [load_scenario(SCENARIOS_DIR / name) for name in BUNDLED_SCENARIO_FILENAMES]


def test_every_bundled_scenario_loads():
    scenarios = _all_scenarios()
    assert len(scenarios) == len(BUNDLED_SCENARIO_FILENAMES)


def test_scenario_ids_are_unique():
    ids = [s.scenario_id for s in _all_scenarios()]
    assert len(ids) == len(set(ids))


def test_catalog_covers_a_difficulty_progression():
    """A newcomer needs somewhere to start. If the easiest bundled scenario
    is intermediate, the catalog has no on-ramp."""
    tiers = {s.difficulty for s in _all_scenarios()}
    assert Difficulty.BEGINNER in tiers, "catalog needs at least one beginner scenario"
    assert Difficulty.INTERMEDIATE in tiers
    assert Difficulty.ADVANCED in tiers


def test_event_counts_match_their_declared_difficulty():
    for scenario in _all_scenarios():
        minimum = _MIN_EVENTS[scenario.difficulty]
        assert scenario.event_count >= minimum, (
            f"{scenario.scenario_id} claims {scenario.difficulty.value} but has only "
            f"{scenario.event_count} events (minimum {minimum})"
        )


def test_intermediate_and_above_contain_benign_activity():
    """Without benign events the precision metric is unmeasurable and the
    exercise implicitly teaches that everything unusual is malicious."""
    for scenario in _all_scenarios():
        if scenario.difficulty not in _TIERS_REQUIRING_BENIGN:
            continue
        benign = [e for e in scenario.timeline if not default_is_opportunity(e)]
        assert benign, (
            f"{scenario.scenario_id} ({scenario.difficulty.value}) has no benign events, "
            "so false-positive scoring cannot be exercised against it"
        )


def test_every_scenario_has_a_usable_answer_key():
    for scenario in _all_scenarios():
        assert len(scenario.answer_key) >= 4, f"{scenario.scenario_id} answer key is too thin"
        event_ids = {e.event_id for e in scenario.timeline}
        for item in scenario.answer_key:
            assert item.question.strip()
            assert item.answer.strip()
            for ref in item.related_event_ids:
                assert ref in event_ids, f"{scenario.scenario_id}/{item.id} references {ref!r}"


def test_every_scenario_declares_learning_objectives_and_tactics():
    for scenario in _all_scenarios():
        assert scenario.learning_objectives, f"{scenario.scenario_id} has no learning objectives"
        assert scenario.mitre_tactics, f"{scenario.scenario_id} declares no ATT&CK tactics"


def test_student_briefing_is_not_a_copy_of_the_instructor_description():
    """The two fields serve different audiences. If a scenario author pastes
    the description into the briefing, students get the answer for free."""
    for scenario in _all_scenarios():
        description = " ".join(scenario.description.split())
        briefing = " ".join(scenario.student_briefing.split())
        assert briefing != description, f"{scenario.scenario_id} briefing duplicates description"
        # And the briefing must not contain a long verbatim run from the
        # description, which is the sloppier version of the same mistake.
        assert description[:80] not in briefing, (
            f"{scenario.scenario_id} briefing opens with the instructor description"
        )


def test_organizations_use_the_reserved_example_tld():
    """RFC 2606 reserves .example for documentation. Using a real-looking
    domain risks a generated scenario referencing a live organization."""
    for scenario in _all_scenarios():
        assert scenario.organization.domain.endswith(".example"), (
            f"{scenario.scenario_id} uses non-reserved domain "
            f"{scenario.organization.domain!r}"
        )
        for key, actor in scenario.actors.items():
            domain = str(actor.email).split("@")[-1]
            if domain.endswith(_SERVICE_IDENTITY_SUFFIXES):
                continue  # provider-dictated format, see the constant's comment
            assert domain.endswith(".example"), (
                f"{scenario.scenario_id}/{key} email domain {domain!r} is not reserved"
            )


def test_catalog_exercises_a_broad_range_of_log_sources():
    """The point of the tool is cross-source correlation; a catalog that
    only ever uses two sources isn't teaching it."""
    used = {
        source.value
        for scenario in _all_scenarios()
        for event in scenario.timeline
        for source in event.log_sources
    }
    assert len(used) >= 6, f"catalog only exercises {sorted(used)}"
