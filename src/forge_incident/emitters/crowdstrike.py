"""CrowdStrike Falcon detection emitter.

Renders `Event`s tagged `LogSource.CROWDSTRIKE` as newline-delimited JSON
shaped like a Falcon detection record as delivered by the Streaming API /
`/detects/entities/summaries/GET` (the shape most commonly forwarded into
a SIEM): a `metadata` envelope plus an `event` body carrying
`DetectName`/`DetectDescription`, `Severity`, `Tactic`/`Technique`,
`ComputerName`, `UserName`, and the process fields
(`FileName`/`CommandLine`/`SHA256HashData`/`ParentProcessId`).

Correlation is automatic — nothing here is invented that isn't already on
the shared `Event`:

- **Process fields** come straight from `Event.process`, so a PID, command
  line, or SHA-256 in a Falcon detection is byte-identical to the one in
  the Windows Sysmon or Linux auditd rendering of the same event.
- **Host** and **user** resolve through `Scenario.get_host`/`get_actor`,
  the same registry every other emitter reads.
- **Tactic/Technique** are the one deliberate exception to the "never
  render `Event.mitre`" rule that applies to raw OS/network logs: a real
  EDR console genuinely *does* display an ATT&CK tactic and technique on
  a detection, so hiding it would make this log source unrealistic. Note
  that this means a scenario using `crowdstrike` hands students ATT&CK
  labels for the events it covers — which is realistic and often the
  pedagogical point (triaging EDR alerts), but if you want students to
  derive the mapping themselves, don't route those events here.

`Event.description` remains instructor-only and is never rendered;
`DetectDescription` uses canonical per-detection text instead.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import (
    EmittedArtifact,
    Emitter,
    humanize_event_type,
    stable_hex_id,
)
from forge_incident.models import EventType, LogSource, Scenario, Severity

__all__ = ["CrowdStrikeEmitter"]

# Falcon numeric severity (1-100) and its display band, plus the canonical
# detection name/description Falcon shows for this class of behavior.
_DETECTION_MAP: dict[EventType, tuple[str, str]] = {
    EventType.MALWARE_EXECUTION: (
        "Known Malware",
        "A process matching a known malicious file was executed.",
    ),
    EventType.MALWARE_DOWNLOAD: (
        "Suspicious Download",
        "A file matching threat intelligence was written to disk.",
    ),
    EventType.PROCESS_INJECTION: (
        "Process Injection",
        "A process injected code into another process.",
    ),
    EventType.PROCESS_CREATED: (
        "Suspicious Process",
        "A process was created with suspicious characteristics.",
    ),
    EventType.PERSISTENCE_ESTABLISHED: (
        "Persistence",
        "A persistence mechanism was established on this host.",
    ),
    EventType.SCHEDULED_TASK_CREATED: (
        "Scheduled Task Persistence",
        "A scheduled task was created to maintain access.",
    ),
    EventType.CREDENTIAL_HARVESTED: (
        "Credential Theft",
        "A process attempted to access credential material.",
    ),
    EventType.PRIVILEGE_ESCALATION: (
        "Privilege Escalation",
        "A process obtained elevated privileges.",
    ),
    EventType.LATERAL_MOVEMENT: (
        "Lateral Movement",
        "Remote execution activity was observed from this host.",
    ),
    EventType.C2_BEACON: (
        "Command and Control",
        "A process established a connection matching C2 behavior.",
    ),
    EventType.DATA_STAGING: (
        "Collection",
        "A process staged files consistent with data collection.",
    ),
    EventType.DATA_EXFILTRATION: (
        "Exfiltration",
        "A process transferred data to an external destination.",
    ),
    EventType.RANSOMWARE_ENCRYPTION: (
        "Ransomware",
        "A process exhibited file-encryption behavior consistent with ransomware.",
    ),
    EventType.LOG_CLEARED: (
        "Defense Evasion",
        "Event log clearing was observed on this host.",
    ),
    EventType.ALERT_TRIGGERED: (
        "Behavioral Detection",
        "Sensor behavioral analytics raised a detection.",
    ),
}

_SEVERITY_SCORE: dict[Severity, tuple[int, str]] = {
    Severity.INFO: (10, "Informational"),
    Severity.LOW: (30, "Low"),
    Severity.MEDIUM: (50, "Medium"),
    Severity.HIGH: (70, "High"),
    Severity.CRITICAL: (90, "Critical"),
}

_PATTERN_DISPOSITION = {
    # Falcon's "what did the sensor do about it" field.
    Severity.CRITICAL: 2048,  # blocked
    Severity.HIGH: 2048,
    Severity.MEDIUM: 1024,  # detected, not blocked
    Severity.LOW: 1024,
    Severity.INFO: 1024,
}


class CrowdStrikeEmitter(Emitter):
    log_source = LogSource.CROWDSTRIKE

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = self.relevant_events(scenario)
        if not events:
            return []

        customer_id = stable_hex_id(scenario.scenario_id, "crowdstrike", "cid", length=32)
        lines: list[str] = []

        for event in events:
            detect_name, detect_description = _DETECTION_MAP.get(
                event.event_type,
                ("Behavioral Detection", humanize_event_type(event.event_type)),
            )
            severity_score, severity_name = _SEVERITY_SCORE[event.severity]
            host = scenario.get_host(event.host) if event.host else None
            actor = scenario.get_actor(event.actor) if event.actor else None
            proc = event.process

            body = {
                "DetectName": detect_name,
                "DetectDescription": detect_description,
                "Severity": severity_score,
                "SeverityName": severity_name,
                "Objective": "Falcon Detection Method",
                # A real Falcon console does surface ATT&CK labels on a
                # detection — see this module's docstring.
                "Tactic": event.mitre.tactic if event.mitre else "Unknown",
                "Technique": event.mitre.technique_name if event.mitre else "Unknown",
                "TechniqueId": event.mitre.technique_id if event.mitre else "",
                "PatternDispositionValue": _PATTERN_DISPOSITION[event.severity],
                "ComputerName": host.hostname if host else "UNKNOWN-HOST",
                "LocalIP": host.ip_address if host else "0.0.0.0",
                "MachineDomain": (
                    scenario.organization.domain if host and host.domain_joined else ""
                ),
                "UserName": actor.username if actor else "UNKNOWN",
                "SensorId": stable_hex_id(
                    host.hostname if host else "unknown", "crowdstrike", "aid", length=32
                ),
                "FalconHostLink": (
                    "https://falcon.crowdstrike.com/activity/detections/detail/"
                    + stable_hex_id(event.event_id, "crowdstrike", "detect", length=32)
                ),
            }

            if proc is not None:
                body.update(
                    {
                        "FileName": proc.name,
                        "CommandLine": proc.command_line,
                        "SHA256HashData": proc.sha256 or "",
                        "ProcessId": proc.pid,
                        "ParentProcessId": proc.ppid or 0,
                        "ParentImageFileName": proc.parent_name or "",
                    }
                )
            elif event.file is not None:
                body.update(
                    {
                        "FileName": event.file.filename,
                        "FilePath": event.file.path,
                        "SHA256HashData": event.file.sha256 or "",
                    }
                )

            record = {
                "metadata": {
                    "customerIDString": customer_id,
                    "offset": event.index,
                    "eventType": "DetectionSummaryEvent",
                    "eventCreationTime": int(event.timestamp.timestamp() * 1000),
                    "version": "1.0",
                },
                "event": body,
            }
            lines.append(json.dumps(record, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path="logs/crowdstrike/detections.jsonl",
                content=content,
                description=(
                    f"CrowdStrike Falcon detection export ({len(events)} detections), "
                    "JSON Lines format."
                ),
            )
        ]
