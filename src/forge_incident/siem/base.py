"""Shared base for SIEM exporters.

The `emitters/` package renders a scenario into *raw log formats* — what
the evidence looked like on the original system. This package does
something different: it renders the same timeline into *SIEM ingest
formats*, so an instructor can load a scenario straight into Splunk,
Elastic, or Microsoft Sentinel and run the exercise inside the tool
students will actually use at work.

Both read from the identical `Scenario`, so a SIEM export and a raw log
export of the same scenario are guaranteed to describe the same incident
with the same identifiers — you can hand students the raw logs and load
the SIEM export yourself for the "here's what your SOC would have seen"
debrief.

Instructor-only fields (`Event.description`, and the narrative half of
`Event.mitre`) are handled the same way emitters handle them, with one
deliberate exception documented per exporter: SIEM schemas have real,
first-class ATT&CK fields (`threat.technique.id` in ECS, for instance),
and a SIEM export with those left blank would be unrealistic and useless
for detection-rule testing. Since SIEM exports are an instructor-side
artifact (you load them into your own tenant; students query the result),
that's an acceptable and intentional difference from the student log
package. `Event.description` is never exported by any of them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from forge_incident.emitters.base import EmittedArtifact
from forge_incident.models import Event, Scenario

__all__ = ["SiemExporter", "resolve_source_ip", "resolve_destination_ip", "event_action"]


class SiemExporter(ABC):
    """One exporter produces one SIEM platform's ingest file(s)."""

    #: Short name used on the CLI: `forge-incident export --format <name>`.
    name: ClassVar[str]
    #: One-line human description shown by `forge-incident export --help`.
    description: ClassVar[str] = ""

    @abstractmethod
    def export(self, scenario: Scenario) -> list[EmittedArtifact]:
        """Render the whole scenario timeline into this platform's format."""


def resolve_source_ip(event: Event, scenario: Scenario) -> str | None:
    """Best available 'where did this come from' IP for an event.

    Mirrors the resolution order the Okta emitter uses, so the same event
    yields the same IP in a SIEM export as in the raw logs.
    """
    if event.network is not None:
        return event.network.src_ip
    if event.cloud is not None:
        return event.cloud.caller_ip
    if event.email is not None and event.email.client_ip:
        return event.email.client_ip
    if event.host is not None:
        return scenario.get_host(event.host).ip_address
    return None


def resolve_destination_ip(event: Event, scenario: Scenario) -> str | None:
    if event.network is not None:
        return event.network.dst_ip
    if event.host is not None:
        return scenario.get_host(event.host).ip_address
    return None


def event_action(event: Event) -> str:
    """The event's type as a SIEM-friendly action string (e.g. 'process_created')."""
    return event.event_type.value
