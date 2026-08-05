"""Shared base class and helpers for all ForgeIncident emitters.

Every emitter takes the *same* `Scenario` and filters its timeline down to
events relevant to it via `Scenario.events_for(log_source)`. Nothing here
invents an identifier that isn't already on the `Event` — the underlying
IP, username, PID, or hash an emitter renders always ultimately comes
from `models.py`, which is what keeps every emitted file mutually
consistent. Where a log format needs a *secondary* ID that the shared
Event model has no reason to carry (a GCP insertId, a PAN-OS session ID,
a synthetic PID for a brute-force noise line), it is derived
deterministically from the event's own `event_id` via `stable_hex_id`/
`stable_int_id` rather than from `random` — so the same scenario + seed
always produces byte-identical secondary IDs too.

An emitter never writes to disk directly. `emit()` returns a list of
`EmittedArtifact` (relative path + text content); `packager.py` is the
only place that actually touches the filesystem or builds ZIPs. This
keeps emitters trivially unit-testable (assert against returned strings)
and keeps "where files land in the package" a single decision made once.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from forge_incident.models import Event, EventType, LogSource, Scenario

__all__ = [
    "EmittedArtifact",
    "Emitter",
    "stable_hex_id",
    "stable_int_id",
    "slugify",
    "group_by_host",
    "humanize_event_type",
    "gcp_rfc3339",
    "message_trace_timestamp",
    "pan_os_timestamp",
    "syslog_timestamp",
    "windows_xml_timestamp",
    "rfc5322_timestamp",
]


@dataclass(frozen=True)
class EmittedArtifact:
    """One rendered file, ready for `packager.py` to place in a package.

    `relative_path` is relative to the package root (e.g.
    'logs/palo_alto/traffic.csv'). Every ForgeIncident log format is text
    (CSV, JSON Lines, syslog, XML, RFC 5322), so `content` is always `str`.
    """

    relative_path: str
    content: str
    description: str = ""


class Emitter(ABC):
    """One emitter renders exactly one `LogSource`'s worth of artifacts."""

    log_source: ClassVar[LogSource]

    def relevant_events(self, scenario: Scenario) -> list[Event]:
        return scenario.events_for(self.log_source)

    @abstractmethod
    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        """Render this emitter's artifacts for a scenario.

        Implementations return an empty list (never raise) when the
        scenario has no events for `self.log_source` — `packager.py`
        skips empty emitters so a package never contains a hollow,
        header-only log file for a source that isn't part of the story.
        """


# --------------------------------------------------------------------------
# Deterministic secondary identifiers
# --------------------------------------------------------------------------


def stable_hex_id(*parts: str, length: int = 16) -> str:
    """A deterministic lowercase-hex ID derived from `parts`."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:length]


def stable_int_id(*parts: str, low: int, high: int) -> int:
    """A deterministic integer in [low, high], derived from `parts`."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    span = high - low + 1
    return low + (int(digest[:8], 16) % span)


def slugify(text: str, max_length: int = 48) -> str:
    """Lowercase, filesystem-safe slug used for generated filenames."""
    keep = []
    for ch in text.lower():
        if ch.isalnum():
            keep.append(ch)
        elif keep and keep[-1] != "-":
            keep.append("-")
    slug = "".join(keep).strip("-")
    return slug[:max_length].rstrip("-") or "untitled"


def humanize_event_type(event_type: EventType) -> str:
    """A short, technical-sounding phrase for an EventType — e.g. 'Process created'.

    Used ONLY as a last-resort fallback message for event types an emitter
    doesn't have a real canonical log message for. Deliberately not the
    same thing as `Event.description`: it names a category of activity
    (what a real product might print as an event's short title), not the
    narrative "here's what happened and why" instructor annotation.
    """
    return event_type.value.replace("_", " ").capitalize()


def group_by_host(events: list[Event], scenario: Scenario) -> dict[str, list[Event]]:
    """Group events by resolved hostname (falling back to 'unassigned-host')."""
    groups: dict[str, list[Event]] = {}
    for event in events:
        hostname = scenario.get_host(event.host).hostname if event.host else "unassigned-host"
        groups.setdefault(hostname, []).append(event)
    return groups


# --------------------------------------------------------------------------
# Timestamp formatting — one canonical formatter per log format, matching
# the real-world tool each emitter's output approximates.
# --------------------------------------------------------------------------


def gcp_rfc3339(ts: datetime) -> str:
    """GCP Cloud Audit Log style: '2026-03-10T08:00:00.123456Z'."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"


def message_trace_timestamp(ts: datetime) -> str:
    """Exchange Online Message Trace style: 'M/D/YYYY H:MM:SS AM/PM' (UTC)."""
    hour12 = ts.hour % 12 or 12
    period = "AM" if ts.hour < 12 else "PM"
    return f"{ts.month}/{ts.day}/{ts.year} {hour12}:{ts.minute:02d}:{ts.second:02d} {period}"


def pan_os_timestamp(ts: datetime) -> str:
    """PAN-OS traffic log style: 'YYYY/MM/DD HH:MM:SS'."""
    return ts.strftime("%Y/%m/%d %H:%M:%S")


def syslog_timestamp(ts: datetime) -> str:
    """RFC 3164 syslog style: 'Mon DD HH:MM:SS' (space-padded day, e.g. 'Mar  3')."""
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


def windows_xml_timestamp(ts: datetime) -> str:
    """Windows Event Log XML style: '2026-03-10T08:00:00.1234567Z' (100ns ticks, 7 digits)."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}0Z"


def rfc5322_timestamp(ts: datetime) -> str:
    """Email header style: 'Tue, 10 Mar 2026 08:00:00 +0000'."""
    return ts.strftime("%a, %d %b %Y %H:%M:%S +0000")
