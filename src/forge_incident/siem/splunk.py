"""Splunk exporter — HTTP Event Collector (HEC) newline-delimited JSON.

Produces a file you can post straight at a HEC endpoint:

    curl -k https://localhost:8088/services/collector/event \\
         -H "Authorization: Splunk <your-hec-token>" \\
         --data-binary @forge-<scenario>-splunk-hec.json

Each line is a HEC envelope (`time`, `host`, `source`, `sourcetype`,
`index`, `event`) wrapping a flat, field-extraction-friendly event body.
The body is deliberately FLAT (`process_command_line`, not a nested
object): Splunk's default JSON field extraction handles flat keys cleanly,
and CIM-style flat names are what most Splunk content expects.

`sourcetype` is derived per event from its first log source
(`forge:windows`, `forge:okta`, ...) so `sourcetype=forge:*` searches work
and each source can be given its own props.conf if desired.

Note (see `siem/base.py`): ATT&CK fields ARE exported — a SIEM export
without them can't be used to validate detection content. `Event.description`
is never exported.
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

__all__ = ["SplunkExporter"]


class SplunkExporter(SiemExporter):
    name = "splunk"
    description = "Splunk HTTP Event Collector (HEC) newline-delimited JSON"

    def export(self, scenario: Scenario) -> list[EmittedArtifact]:
        index = "forge_incident"
        lines: list[str] = []

        for event in scenario.timeline:
            actor = scenario.get_actor(event.actor) if event.actor else None
            host = scenario.get_host(event.host) if event.host else None
            primary_source = event.log_sources[0].value if event.log_sources else "unknown"

            body: dict[str, object] = {
                "event_id": event.event_id,
                "event_index": event.index,
                "action": event_action(event),
                "severity": event.severity.value,
                "scenario_id": scenario.scenario_id,
                "scenario_seed": scenario.seed,
                "org_name": scenario.organization.name,
                "org_domain": scenario.organization.domain,
                "log_sources": ",".join(s.value for s in event.log_sources),
            }
            if event.tags:
                body["tags"] = ",".join(event.tags)

            src_ip = resolve_source_ip(event, scenario)
            dest_ip = resolve_destination_ip(event, scenario)
            if src_ip:
                body["src_ip"] = src_ip
            if dest_ip:
                body["dest_ip"] = dest_ip

            if actor is not None:
                body.update(
                    {
                        "user": actor.username,
                        "user_email": str(actor.email),
                        "user_display_name": actor.display_name,
                        "user_is_privileged": actor.is_privileged,
                    }
                )
            if host is not None:
                body.update(
                    {
                        "dest_host": host.hostname,
                        "dest_host_ip": host.ip_address,
                        "dest_host_os": host.os.value,
                    }
                )
            if event.process is not None:
                proc = event.process
                body.update(
                    {
                        "process_id": proc.pid,
                        "process_name": proc.name,
                        "process_command_line": proc.command_line,
                        "parent_process_id": proc.ppid,
                        "parent_process_name": proc.parent_name,
                        "process_hash_sha256": proc.sha256,
                    }
                )
            if event.file is not None:
                body.update(
                    {
                        "file_name": event.file.filename,
                        "file_path": event.file.path,
                        "file_size": event.file.size_bytes,
                        "file_hash_sha256": event.file.sha256,
                        "file_hash_md5": event.file.md5,
                    }
                )
            if event.network is not None:
                net = event.network
                body.update(
                    {
                        "src_port": net.src_port,
                        "dest_port": net.dst_port,
                        "transport": net.protocol.value,
                        "network_action": net.action.value,
                        "app": net.app,
                        "bytes_out": net.bytes_sent,
                        "bytes_in": net.bytes_received,
                        "rule_name": net.rule_name,
                    }
                )
            if event.email is not None:
                mail = event.email
                body.update(
                    {
                        "message_id": mail.message_id,
                        "src_user": str(mail.sender),
                        "recipient": ",".join(str(r) for r in mail.recipients),
                        "subject": mail.subject,
                        "email_direction": mail.direction.value,
                        "spf": mail.spf.value,
                        "dkim": mail.dkim.value,
                        "dmarc": mail.dmarc.value,
                        "has_attachment": mail.has_attachment,
                        "attachment_name": mail.attachment_name,
                    }
                )
            if event.cloud is not None:
                cloud = event.cloud
                body.update(
                    {
                        "cloud_method": cloud.method_name,
                        "cloud_service": cloud.service_name,
                        "cloud_resource": cloud.resource_name,
                        "cloud_caller_ip": cloud.caller_ip,
                        "cloud_status": cloud.status_code,
                        "cloud_account_id": cloud.project_id,
                        "cloud_region": cloud.region,
                        "user_agent": cloud.user_agent,
                    }
                )
            if event.mitre is not None:
                body.update(
                    {
                        "mitre_technique_id": event.mitre.technique_id,
                        "mitre_technique": event.mitre.technique_name,
                        "mitre_tactic": event.mitre.tactic,
                    }
                )

            envelope = {
                "time": event.timestamp.timestamp(),
                "host": host.hostname if host else scenario.organization.name,
                "source": f"forge-incident:{scenario.scenario_id}",
                "sourcetype": f"forge:{primary_source}",
                "index": index,
                "event": {k: v for k, v in body.items() if v not in (None, "")},
            }
            lines.append(json.dumps(envelope, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"siem/splunk/{scenario.scenario_id}-hec.json",
                content=content,
                description=(
                    f"Splunk HEC events ({len(scenario.timeline)} events) for "
                    f"index='{index}', sourcetype='forge:*'."
                ),
            )
        ]
