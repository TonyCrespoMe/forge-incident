"""SIEM ingest-format exporters.

Where `emitters/` renders a scenario as raw evidence files (what the logs
looked like on the original systems), this package renders the same
timeline into formats you can load directly into a SIEM — so an exercise
can be run inside Splunk, Elastic, or Microsoft Sentinel rather than
against flat files.

Both paths read the same validated `Scenario`, so identifiers stay
consistent between the student's raw log package and whatever you've
loaded into your SIEM tenant.

Adding a platform = one `SiemExporter` subclass + one line in `ALL_EXPORTERS`.
"""

from __future__ import annotations

from forge_incident.emitters.base import EmittedArtifact
from forge_incident.models import Scenario
from forge_incident.siem.base import SiemExporter
from forge_incident.siem.elastic import ElasticExporter
from forge_incident.siem.sentinel import SentinelExporter
from forge_incident.siem.splunk import SplunkExporter

__all__ = [
    "SiemExporter",
    "SplunkExporter",
    "ElasticExporter",
    "SentinelExporter",
    "ALL_EXPORTERS",
    "EXPORTER_NAMES",
    "get_exporter",
    "export_scenario",
]

ALL_EXPORTERS: tuple[SiemExporter, ...] = (
    SplunkExporter(),
    ElasticExporter(),
    SentinelExporter(),
)

EXPORTER_NAMES: tuple[str, ...] = tuple(exporter.name for exporter in ALL_EXPORTERS)


class UnknownExporterError(Exception):
    """Raised when a caller asks for a SIEM format that doesn't exist."""


def get_exporter(name: str) -> SiemExporter:
    key = name.strip().lower()
    for exporter in ALL_EXPORTERS:
        if exporter.name == key:
            return exporter
    raise UnknownExporterError(
        f"Unknown SIEM export format {name!r}. Choose from: {', '.join(EXPORTER_NAMES)}"
    )


def export_scenario(
    scenario: Scenario, formats: tuple[str, ...] | list[str] | None = None
) -> list[EmittedArtifact]:
    """Export a scenario to one or more SIEM formats (default: all of them)."""
    chosen = ALL_EXPORTERS if not formats else tuple(get_exporter(name) for name in formats)
    artifacts: list[EmittedArtifact] = []
    for exporter in chosen:
        artifacts.extend(exporter.export(scenario))
    return artifacts
