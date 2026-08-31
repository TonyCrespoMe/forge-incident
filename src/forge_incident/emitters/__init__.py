"""All ForgeIncident log/artifact emitters.

`BUILTIN_EMITTERS` is the registry of formats that ship with the project.
Adding a new *built-in* log format means writing one `Emitter` subclass
and adding one line to that tuple — nothing else in the pipeline changes.

`ALL_EMITTERS` is what `packager.py` and `cli.py` actually run, and is
`BUILTIN_EMITTERS` plus any third-party plugin emitters discovered at
import time (see `registry.py` for the two discovery mechanisms). Plugins
that fail to load never break generation — they're collected into
`PLUGIN_DISCOVERY.errors` and surfaced by `forge-incident plugins`.
"""

from __future__ import annotations

from forge_incident.emitters.aws_cloudtrail import AwsCloudTrailEmitter
from forge_incident.emitters.azure_activity import AzureActivityEmitter
from forge_incident.emitters.base import EmittedArtifact, Emitter
from forge_incident.emitters.crowdstrike import CrowdStrikeEmitter
from forge_incident.emitters.email_eml import EmailEmitter
from forge_incident.emitters.firewall_syslog import FirewallSyslogEmitter
from forge_incident.emitters.gcp_audit import GcpAuditEmitter
from forge_incident.emitters.iis import IisEmitter
from forge_incident.emitters.linux import LinuxEmitter
from forge_incident.emitters.okta import OktaEmitter
from forge_incident.emitters.outlook_message_trace import OutlookMessageTraceEmitter
from forge_incident.emitters.palo_alto import PaloAltoEmitter
from forge_incident.emitters.registry import (
    DiscoveryResult,
    PluginEmitter,
    discover_plugin_emitters,
    load_emitters,
)
from forge_incident.emitters.windows import WindowsEmitter
from forge_incident.models import Scenario

__all__ = [
    "EmittedArtifact",
    "Emitter",
    "PluginEmitter",
    "GcpAuditEmitter",
    "AwsCloudTrailEmitter",
    "AzureActivityEmitter",
    "OktaEmitter",
    "CrowdStrikeEmitter",
    "IisEmitter",
    "OutlookMessageTraceEmitter",
    "PaloAltoEmitter",
    "FirewallSyslogEmitter",
    "LinuxEmitter",
    "WindowsEmitter",
    "EmailEmitter",
    "BUILTIN_EMITTERS",
    "ALL_EMITTERS",
    "PLUGIN_DISCOVERY",
    "DiscoveryResult",
    "discover_plugin_emitters",
    "load_emitters",
    "refresh_emitters",
    "run_all",
]

BUILTIN_EMITTERS: tuple[Emitter, ...] = (
    GcpAuditEmitter(),
    AwsCloudTrailEmitter(),
    AzureActivityEmitter(),
    OktaEmitter(),
    CrowdStrikeEmitter(),
    IisEmitter(),
    OutlookMessageTraceEmitter(),
    PaloAltoEmitter(),
    FirewallSyslogEmitter(),
    LinuxEmitter(),
    WindowsEmitter(),
    EmailEmitter(),
)

ALL_EMITTERS, PLUGIN_DISCOVERY = load_emitters(BUILTIN_EMITTERS)


def refresh_emitters(plugins_dir: str | None = None) -> DiscoveryResult:
    """Re-run plugin discovery and update `ALL_EMITTERS` in place.

    Used by the web UI (where a user may drop a plugin file in mid-session
    and expect it to be picked up without restarting) and by tests that
    point at a temporary plugins directory.
    """
    global ALL_EMITTERS, PLUGIN_DISCOVERY
    ALL_EMITTERS, PLUGIN_DISCOVERY = load_emitters(BUILTIN_EMITTERS, plugins_dir=plugins_dir)
    return PLUGIN_DISCOVERY


def run_all(
    scenario: Scenario, emitters: tuple[Emitter, ...] | None = None
) -> list[EmittedArtifact]:
    """Run every emitter against a scenario and flatten the results.

    Emitters that find no relevant events for their log source contribute
    nothing (see `Emitter.emit`'s contract), so the result only ever
    contains artifacts for log sources the scenario actually uses.

    A plugin emitter that raises is caught and skipped with its failure
    recorded in `PLUGIN_DISCOVERY.errors`, so one bad third-party emitter
    can't destroy an otherwise valid package. Built-in emitters are NOT
    wrapped this way — a built-in raising is a bug in this project and
    should surface loudly.
    """
    if emitters is None:
        emitters = ALL_EMITTERS

    artifacts: list[EmittedArtifact] = []
    for emitter in emitters:
        if emitter in BUILTIN_EMITTERS:
            artifacts.extend(emitter.emit(scenario))
            continue
        try:
            artifacts.extend(emitter.emit(scenario))
        except Exception as exc:
            PLUGIN_DISCOVERY.errors.append(
                (f"plugin:{type(emitter).__name__}", f"raised during emit(): {exc}")
            )
    return artifacts
