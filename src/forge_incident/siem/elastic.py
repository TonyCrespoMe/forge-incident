"""Elastic / OpenSearch exporter — ECS-mapped bulk NDJSON.

Produces a file ready for the `_bulk` API:

    curl -H 'Content-Type: application/x-ndjson' \\
         -XPOST 'http://localhost:9200/_bulk' \\
         --data-binary @forge-<scenario>-elastic-bulk.ndjson

Every event is mapped onto Elastic Common Schema (ECS) field names —
`@timestamp`, `event.*`, `source.ip`, `destination.ip`, `user.*`,
`host.*`, `process.*`, `file.*`, `email.*`, `threat.technique.*` — rather
than dumped as an arbitrary blob, so Kibana's out-of-the-box visualizations
and any ECS-based detection rules work against a generated scenario
immediately.

Note (see `siem/base.py`): `threat.*` fields ARE populated from
`Event.mitre`, because a SIEM export with no ATT&CK mapping can't be used
to test detection rules — the whole reason to load one. `Event.description`
is never exported.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import EmittedArtifact, stable_hex_id
from forge_incident.models import Scenario, Severity
from forge_incident.siem.base import (
    SiemExporter,
    event_action,
    resolve_destination_ip,
    resolve_source_ip,
)

__all__ = ["ElasticExporter"]

# ECS event.severity is a long; map our label onto the conventional 0-100
# scale Elastic Security uses for rule severity.
_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 21,
    Severity.MEDIUM: 47,
    Severity.HIGH: 73,
    Severity.CRITICAL: 99,
}

# ECS event.category is a controlled vocabulary — using arbitrary strings
# here would break Kibana's prebuilt dashboards, so every event type is
# mapped onto a real allowed value.
_CATEGORY_BY_PREFIX: list[tuple[tuple[str, ...], list[str]]] = [
    (("account_", "mfa_", "password_", "user_", "group_", "privilege_"), ["authentication", "iam"]),
    (("phishing_", "email_", "attachment_", "credential_"), ["email"]),
    (("malware_",), ["malware", "process"]),
    (("process_", "persistence_", "scheduled_task_"), ["process"]),
    (("registry_",), ["registry"]),
    (("file_", "data_staging"), ["file"]),
    (("dns_",), ["network", "dns"]),
    (("network_", "c2_", "lateral_"), ["network"]),
    (("data_exfiltration",), ["network"]),
    (("cloud_",), ["configuration"]),
    (("log_cleared", "ransomware_"), ["malware"]),
    (("alert_",), ["intrusion_detection"]),
]


def _categories(event_type_value: str) -> list[str]:
    for prefixes, categories in _CATEGORY_BY_PREFIX:
        if event_type_value.startswith(prefixes):
            return categories
    return ["process"]


def _prune(obj: dict) -> dict:
    """Drop empty leaves so documents stay clean in Kibana's field browser."""
    cleaned = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            nested = _prune(value)
            if nested:
                cleaned[key] = nested
        elif value not in (None, "", [], {}):
            cleaned[key] = value
    return cleaned


class ElasticExporter(SiemExporter):
    name = "elastic"
    description = "Elastic/OpenSearch ECS-mapped documents as _bulk NDJSON"

    def export(self, scenario: Scenario) -> list[EmittedArtifact]:
        index = f"forge-incident-{scenario.scenario_id}"
        lines: list[str] = []

        for event in scenario.timeline:
            actor = scenario.get_actor(event.actor) if event.actor else None
            host = scenario.get_host(event.host) if event.host else None
            doc_id = stable_hex_id(event.event_id, "elastic", "doc", length=20)

            doc = {
                "@timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
                "ecs": {"version": "8.11.0"},
                "event": {
                    "id": event.event_id,
                    "kind": "alert" if event.event_type.value == "alert_triggered" else "event",
                    "category": _categories(event.event_type.value),
                    "action": event_action(event),
                    "severity": _SEVERITY_SCORE[event.severity],
                    "dataset": "forge_incident."
                    + (event.log_sources[0].value if event.log_sources else "unknown"),
                    "module": "forge_incident",
                    "sequence": event.index,
                },
                "organization": {"name": scenario.organization.name},
                "labels": {
                    "scenario_id": scenario.scenario_id,
                    "scenario_seed": str(scenario.seed),
                    "log_sources": [s.value for s in event.log_sources],
                    "tags": event.tags,
                },
                "source": {"ip": resolve_source_ip(event, scenario)},
                "destination": {"ip": resolve_destination_ip(event, scenario)},
            }

            if actor is not None:
                doc["user"] = {
                    "name": actor.username,
                    "email": str(actor.email),
                    "full_name": actor.display_name,
                    "domain": scenario.organization.domain,
                }
            if host is not None:
                doc["host"] = {
                    "hostname": host.hostname,
                    "name": host.hostname,
                    "ip": [host.ip_address],
                    "mac": [host.mac_address] if host.mac_address else [],
                    "os": {"family": host.os.value, "version": host.os_version},
                }
            if event.process is not None:
                proc = event.process
                doc["process"] = {
                    "pid": proc.pid,
                    "name": proc.name,
                    "command_line": proc.command_line,
                    "hash": {"sha256": proc.sha256},
                    "parent": {"pid": proc.ppid, "name": proc.parent_name},
                }
            if event.file is not None:
                doc["file"] = {
                    "name": event.file.filename,
                    "path": event.file.path,
                    "size": event.file.size_bytes,
                    "hash": {"sha256": event.file.sha256, "md5": event.file.md5},
                }
            if event.network is not None:
                net = event.network
                doc["network"] = {
                    "transport": net.protocol.value,
                    "application": net.app,
                    "bytes": (net.bytes_sent or 0) + (net.bytes_received or 0),
                }
                doc["source"]["port"] = net.src_port
                doc["source"]["bytes"] = net.bytes_sent
                doc["destination"]["port"] = net.dst_port
                doc["destination"]["bytes"] = net.bytes_received
                doc["event"]["outcome"] = (
                    "success" if net.action.value == "allow" else "failure"
                )
            if event.email is not None:
                mail = event.email
                doc["email"] = {
                    "message_id": mail.message_id,
                    "subject": mail.subject,
                    "from": {"address": [str(mail.sender)]},
                    "to": {"address": [str(r) for r in mail.recipients]},
                    "direction": mail.direction.value,
                    "attachments": (
                        [{"file": {"name": mail.attachment_name}}] if mail.has_attachment else []
                    ),
                }
            if event.cloud is not None:
                doc["cloud"] = {
                    "provider": event.cloud.service_name,
                    "account": {"id": event.cloud.project_id},
                    "region": event.cloud.region,
                }
                doc["event"]["outcome"] = (
                    "success" if event.cloud.status_code == "OK" else "failure"
                )
            if event.mitre is not None:
                doc["threat"] = {
                    "framework": "MITRE ATT&CK",
                    "technique": {
                        "id": event.mitre.technique_id,
                        "name": event.mitre.technique_name,
                    },
                    "tactic": {"name": event.mitre.tactic},
                }

            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}, separators=(",", ":")))
            lines.append(json.dumps(_prune(doc), separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"siem/elastic/{scenario.scenario_id}-bulk.ndjson",
                content=content,
                description=(
                    f"Elastic _bulk NDJSON, ECS 8.11 mapped ({len(scenario.timeline)} documents) "
                    f"targeting index '{index}'."
                ),
            )
        ]
