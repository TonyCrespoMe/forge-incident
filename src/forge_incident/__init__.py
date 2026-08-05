"""ForgeIncident: local-first, deterministic DFIR/purple-team training packages.

Public re-exports here are intentionally limited to the shared data model —
`cli.py`, `emitters/`, `llm/`, and `packager.py` are implementation details
that consumers should import explicitly (e.g. `from forge_incident.emitters import gcp_audit`).
"""

from forge_incident.models import (
    AnswerKeyItem,
    CloudApiCall,
    Difficulty,
    EmailArtifact,
    Event,
    EventType,
    FileInfo,
    Host,
    HostType,
    Identity,
    LogSource,
    MitreTechnique,
    NetworkInfo,
    OperatingSystem,
    OrgProfile,
    ProcessInfo,
    Scenario,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AnswerKeyItem",
    "CloudApiCall",
    "Difficulty",
    "EmailArtifact",
    "Event",
    "EventType",
    "FileInfo",
    "Host",
    "HostType",
    "Identity",
    "LogSource",
    "MitreTechnique",
    "NetworkInfo",
    "OperatingSystem",
    "OrgProfile",
    "ProcessInfo",
    "Scenario",
    "Severity",
]
