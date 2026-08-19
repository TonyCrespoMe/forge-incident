"""Microsoft Sentinel exporter — Log Analytics custom-table JSON.

Produces a JSON array ready for the Log Analytics ingestion API (the
Logs Ingestion API against a DCR, or the legacy HTTP Data Collector API),
landing in a custom table named `ForgeIncident_CL`:

    az monitor log-analytics ... (or POST the file to your DCE endpoint)

Sentinel/Log Analytics conventions this follows:

- **`TimeGenerated`** is the reserved timestamp column Sentinel sorts and
  scopes queries by; it must be ISO-8601.
- **PascalCase column names.** Log Analytics custom columns conventionally
  use PascalCase, and the `_CL` table suffix plus per-column type suffixes
  (`_s` string, `_d` double, `_b` bool) are appended by Azure itself on
  ingest — so they're deliberately NOT hardcoded here.
- **Flat columns.** KQL is far easier to write against flat columns than
  nested dynamic objects, so the schema is flattened the same way the
  Splunk exporter flattens.

A starter KQL hunting query is emitted alongside the data as a second
artifact, so an instructor can paste something working into the Sentinel
Logs blade immediately rather than reverse-engineering the column names.

Note (see `siem/base.py`): ATT&CK columns ARE exported — Sentinel analytics
rules map to ATT&CK natively and a scenario without them can't exercise
that. `Event.description` is never exported.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import EmittedArtifact
from forge_incident.models import Scenario
from forge_incident.siem.base import (
    SiemExporter,
    event_action,
    resolve_destination_ip,
    resolve_source_ip,
)

__all__ = ["SentinelExporter"]

_TABLE_NAME = "ForgeIncident_CL"


class SentinelExporter(SiemExporter):
    name = "sentinel"
    description = "Microsoft Sentinel / Log Analytics custom-table JSON (+ starter KQL)"

    def export(self, scenario: Scenario) -> list[EmittedArtifact]:
        rows: list[dict[str, object]] = []

        for event in scenario.timeline:
            actor = scenario.get_actor(event.actor) if event.actor else None
            host = scenario.get_host(event.host) if event.host else None

            row: dict[str, object] = {
                "TimeGenerated": event.timestamp.isoformat().replace("+00:00", "Z"),
                "EventId": event.event_id,
                "EventIndex": event.index,
                "Activity": event_action(event),
                "Severity": event.severity.value,
                "ScenarioId": scenario.scenario_id,
                "ScenarioSeed": scenario.seed,
                "OrganizationName": scenario.organization.name,
                "OrganizationDomain": scenario.organization.domain,
                "LogSources": ",".join(s.value for s in event.log_sources),
            }
            if event.tags:
                row["Tags"] = ",".join(event.tags)

            src_ip = resolve_source_ip(event, scenario)
            dest_ip = resolve_destination_ip(event, scenario)
            if src_ip:
                row["SourceIP"] = src_ip
            if dest_ip:
                row["DestinationIP"] = dest_ip

            if actor is not None:
                row.update(
                    {
                        "AccountName": actor.username,
                        "AccountUPN": str(actor.email),
                        "AccountDisplayName": actor.display_name,
                        "AccountIsPrivileged": actor.is_privileged,
                    }
                )
            if host is not None:
                row.update(
                    {
                        "Computer": host.hostname,
                        "ComputerIP": host.ip_address,
                        "OSType": host.os.value,
                    }
                )
            if event.process is not None:
                proc = event.process
                row.update(
                    {
                        "ProcessId": proc.pid,
                        "ProcessName": proc.name,
                        "CommandLine": proc.command_line,
                        "ParentProcessId": proc.ppid,
                        "ParentProcessName": proc.parent_name,
                        "ProcessSHA256": proc.sha256,
                    }
                )
            if event.file is not None:
                row.update(
                    {
                        "FileName": event.file.filename,
                        "FilePath": event.file.path,
                        "FileSize": event.file.size_bytes,
                        "FileSHA256": event.file.sha256,
                        "FileMD5": event.file.md5,
                    }
                )
            if event.network is not None:
                net = event.network
                row.update(
                    {
                        "SourcePort": net.src_port,
                        "DestinationPort": net.dst_port,
                        "Protocol": net.protocol.value,
                        "NetworkAction": net.action.value,
                        "ApplicationProtocol": net.app,
                        "SentBytes": net.bytes_sent,
                        "ReceivedBytes": net.bytes_received,
                        "RuleName": net.rule_name,
                    }
                )
            if event.email is not None:
                mail = event.email
                row.update(
                    {
                        "EmailMessageId": mail.message_id,
                        "EmailSender": str(mail.sender),
                        "EmailRecipients": ",".join(str(r) for r in mail.recipients),
                        "EmailSubject": mail.subject,
                        "EmailDirection": mail.direction.value,
                        "EmailHasAttachment": mail.has_attachment,
                        "EmailAttachmentName": mail.attachment_name,
                    }
                )
            if event.cloud is not None:
                cloud = event.cloud
                row.update(
                    {
                        "CloudOperation": cloud.method_name,
                        "CloudService": cloud.service_name,
                        "CloudResource": cloud.resource_name,
                        "CloudCallerIP": cloud.caller_ip,
                        "CloudStatus": cloud.status_code,
                        "CloudAccountId": cloud.project_id,
                        "CloudRegion": cloud.region,
                        "UserAgent": cloud.user_agent,
                    }
                )
            if event.mitre is not None:
                row.update(
                    {
                        "MitreTechniqueId": event.mitre.technique_id,
                        "MitreTechnique": event.mitre.technique_name,
                        "MitreTactic": event.mitre.tactic,
                    }
                )

            rows.append({k: v for k, v in row.items() if v not in (None, "")})

        data = json.dumps(rows, indent=2) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"siem/sentinel/{scenario.scenario_id}-{_TABLE_NAME}.json",
                content=data,
                description=(
                    f"Microsoft Sentinel Log Analytics rows ({len(rows)} events) for custom "
                    f"table '{_TABLE_NAME}'."
                ),
            ),
            EmittedArtifact(
                relative_path=f"siem/sentinel/{scenario.scenario_id}-starter-queries.kql",
                content=_starter_kql(scenario),
                description="Starter KQL hunting queries for the ingested scenario.",
            ),
        ]


def _starter_kql(scenario: Scenario) -> str:
    """Working KQL against the exported table. Column names match the exporter above.

    Kept intentionally instructor-facing but spoiler-light: these are the
    queries you'd write to START an investigation, not the answer.
    """
    header = f"// ForgeIncident starter queries — scenario: {scenario.scenario_id}"
    return f"""{header} (seed {scenario.seed})
// Table: {_TABLE_NAME}   (Azure appends type suffixes like _s/_d/_b on ingest;
// if a column doesn't resolve, check its exact name with: {_TABLE_NAME} | getschema)

// 1. Full timeline, oldest first — start here.
{_TABLE_NAME}
| where ScenarioId_s == "{scenario.scenario_id}"
| sort by TimeGenerated asc
| project TimeGenerated, Activity_s, Severity_s, AccountName_s, Computer_s,
          SourceIP_s, DestinationIP_s

// 2. High-signal events only.
{_TABLE_NAME}
| where ScenarioId_s == "{scenario.scenario_id}"
| where Severity_s in ("high", "critical")
| sort by TimeGenerated asc

// 3. Which external IPs talked to us, and how much data moved?
{_TABLE_NAME}
| where ScenarioId_s == "{scenario.scenario_id}"
| where isnotempty(SourceIP_s)
| summarize Events = count(),
            BytesOut = sum(SentBytes_d),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
        by SourceIP_s
| sort by BytesOut desc

// 4. Process ancestry — spot the suspicious parent/child pairs.
{_TABLE_NAME}
| where ScenarioId_s == "{scenario.scenario_id}"
| where isnotempty(ProcessName_s)
| project TimeGenerated, Computer_s, ParentProcessName_s, ProcessName_s, CommandLine_s

// 5. ATT&CK coverage of what actually happened (instructor view — spoilers).
{_TABLE_NAME}
| where ScenarioId_s == "{scenario.scenario_id}"
| where isnotempty(MitreTactic_s)
| summarize Techniques = make_set(MitreTechniqueId_s), Events = count() by MitreTactic_s
"""
