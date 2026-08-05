"""All ForgeIncident log/artifact emitters.

`ALL_EMITTERS` is the single registry `packager.py` (and `cli.py`, for a
"what would this scenario produce" preview) iterate over. Adding a new
log format means writing one `Emitter` subclass and adding one line here
— nothing else needs to change.
"""

from __future__ import annotations

from forge_incident.emitters.base import EmittedArtifact, Emitter
from forge_incident.emitters.email_eml import EmailEmitter
from forge_incident.emitters.gcp_audit import GcpAuditEmitter
from forge_incident.emitters.linux import LinuxEmitter
from forge_incident.emitters.outlook_message_trace import OutlookMessageTraceEmitter
from forge_incident.emitters.palo_alto import PaloAltoEmitter
from forge_incident.emitters.windows import WindowsEmitter
from forge_incident.models import Scenario

__all__ = [
    "EmittedArtifact",
    "Emitter",
    "GcpAuditEmitter",
    "OutlookMessageTraceEmitter",
    "PaloAltoEmitter",
    "LinuxEmitter",
    "WindowsEmitter",
    "EmailEmitter",
    "ALL_EMITTERS",
    "run_all",
]

ALL_EMITTERS: tuple[Emitter, ...] = (
    GcpAuditEmitter(),
    OutlookMessageTraceEmitter(),
    PaloAltoEmitter(),
    LinuxEmitter(),
    WindowsEmitter(),
    EmailEmitter(),
)


def run_all(scenario: Scenario, emitters: tuple[Emitter, ...] = ALL_EMITTERS) -> list[EmittedArtifact]:
    """Run every emitter against a scenario and flatten the results.

    Emitters that find no relevant events for their log source contribute
    nothing (see `Emitter.emit`'s contract), so the result only ever
    contains artifacts for log sources the scenario actually uses.
    """
    artifacts: list[EmittedArtifact] = []
    for emitter in emitters:
        artifacts.extend(emitter.emit(scenario))
    return artifacts
