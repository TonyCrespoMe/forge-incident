"""Unit tests for the shared data model (models.py).

These exercise validation directly against hand-built `Scenario`/`Event`
objects (not YAML) so failures point straight at the model, not at
scenario_loader's YAML handling (see test_scenario_loader.py for that).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from forge_incident.models import (
    Event,
    EventType,
    Host,
    Identity,
    LogSource,
    OrgProfile,
    Scenario,
)

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(event_id="e0", index=0, timestamp=_T0, actor="victim", host="h1", **overrides):
    kwargs = dict(
        event_id=event_id,
        index=index,
        timestamp=timestamp,
        event_type=EventType.ACCOUNT_LOGIN_SUCCESS,
        log_sources=[LogSource.WINDOWS],
        actor=actor,
        host=host,
        description="A login event.",
    )
    kwargs.update(overrides)
    return Event(**kwargs)


def _scenario(**overrides):
    kwargs = dict(
        scenario_id="test-scenario",
        title="Test Scenario",
        description="Full instructor narrative.",
        student_briefing="Non-spoiler briefing.",
        seed=1,
        organization=OrgProfile(name="Acme", domain="acme.example"),
        actors={"victim": Identity(username="v", email="v@acme.example", display_name="Vicky")},
        hosts={"h1": Host(hostname="H1", ip_address="10.0.0.1")},
        timeline=[_event()],
    )
    kwargs.update(overrides)
    return Scenario(**kwargs)


def test_minimal_scenario_builds():
    scenario = _scenario()
    assert scenario.event_count == 1
    assert scenario.start_time == scenario.end_time == _T0
    assert scenario.duration == timedelta(0)


def test_get_actor_and_get_host():
    scenario = _scenario()
    assert scenario.get_actor("victim").username == "v"
    assert scenario.get_host("h1").hostname == "H1"
    with pytest.raises(KeyError):
        scenario.get_actor("nobody")


def test_events_for_filters_by_log_source():
    scenario = _scenario(
        timeline=[
            _event(event_id="e0", index=0, log_sources=[LogSource.WINDOWS]),
            _event(
                event_id="e1",
                index=1,
                timestamp=_T0 + timedelta(minutes=1),
                log_sources=[LogSource.LINUX],
            ),
        ]
    )
    assert [e.event_id for e in scenario.events_for(LogSource.WINDOWS)] == ["e0"]
    assert [e.event_id for e in scenario.events_for(LogSource.LINUX)] == ["e1"]
    assert scenario.events_for(LogSource.GCP_AUDIT) == []


def test_unknown_actor_reference_is_rejected():
    with pytest.raises(ValidationError):
        _scenario(timeline=[_event(actor="nobody")])


def test_unknown_host_reference_is_rejected():
    with pytest.raises(ValidationError):
        _scenario(timeline=[_event(host="nowhere")])


def test_duplicate_event_id_is_rejected():
    with pytest.raises(ValidationError):
        _scenario(
            timeline=[
                _event(event_id="dupe", index=0),
                _event(event_id="dupe", index=1, timestamp=_T0 + timedelta(minutes=1)),
            ]
        )


def test_timeline_must_be_chronologically_sorted():
    with pytest.raises(ValidationError):
        _scenario(
            timeline=[
                _event(event_id="e0", index=0, timestamp=_T0 + timedelta(minutes=5)),
                _event(event_id="e1", index=1, timestamp=_T0),
            ]
        )


def test_answer_key_referencing_unknown_event_id_is_rejected():
    from forge_incident.models import AnswerKeyItem

    with pytest.raises(ValidationError):
        _scenario(
            answer_key=[
                AnswerKeyItem(
                    id="q1", question="?", answer="!", related_event_ids=["does-not-exist"]
                )
            ]
        )


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        _event(timestamp=datetime(2026, 1, 1))  # no tzinfo


def test_invalid_mitre_technique_id_is_rejected():
    from forge_incident.models import MitreTechnique

    with pytest.raises(ValidationError):
        MitreTechnique(technique_id="not-a-technique", technique_name="x", tactic="y")


def test_email_attachment_requires_name():
    from forge_incident.models import EmailArtifact

    with pytest.raises(ValidationError):
        EmailArtifact(
            message_id="<a@b>",
            sender="a@b.example",
            recipients=["c@d.example"],
            subject="s",
            has_attachment=True,
            # attachment_name intentionally omitted
        )
