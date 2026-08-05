"""GCP Cloud Audit Log emitter.

Renders `Event`s carrying a `cloud` payload as newline-delimited JSON
(JSON Lines), approximating the structure of a Cloud Audit Log entry as
you'd see it via `gcloud logging read --format=json` or a Cloud Logging
export sink: a `protoPayload` of `@type
type.googleapis.com/google.cloud.audit.AuditLog` nested under the usual
LogEntry envelope (`insertId`, `timestamp`, `severity`, `resource`).

Only the fields ForgeIncident's shared `CloudApiCall` model actually
carries are populated; this is a representative subset of a real audit
log entry, not a byte-for-byte schema match.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import EmittedArtifact, Emitter, gcp_rfc3339, stable_hex_id
from forge_incident.models import LogSource, Scenario, Severity

__all__ = ["GcpAuditEmitter"]

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.INFO: "NOTICE",
    Severity.LOW: "NOTICE",
    Severity.MEDIUM: "WARNING",
    Severity.HIGH: "ERROR",
    Severity.CRITICAL: "CRITICAL",
}


class GcpAuditEmitter(Emitter):
    log_source = LogSource.GCP_AUDIT

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.cloud is not None]
        if not events:
            return []

        project_id = scenario.organization.gcp_project_id or "unknown-project"
        lines: list[str] = []

        for event in events:
            cloud = event.cloud
            assert cloud is not None  # filtered above; narrows type for readers
            principal_email = scenario.get_actor(event.actor).email if event.actor else "unknown"

            entry = {
                "insertId": stable_hex_id(event.event_id, "gcp_audit", "insertId", length=20),
                "logName": f"projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity",
                "severity": _SEVERITY_MAP[event.severity],
                "timestamp": gcp_rfc3339(event.timestamp),
                "receiveTimestamp": gcp_rfc3339(event.timestamp),
                "resource": {
                    "type": "project",
                    "labels": {"project_id": cloud.project_id or project_id},
                },
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": cloud.service_name,
                    "methodName": cloud.method_name,
                    "resourceName": cloud.resource_name,
                    "authenticationInfo": {"principalEmail": principal_email},
                    "requestMetadata": {
                        "callerIp": cloud.caller_ip,
                        "callerSuppliedUserAgent": cloud.user_agent or "",
                    },
                    "status": (
                        {"code": 0, "message": "OK"}
                        if cloud.status_code == "OK"
                        else {"code": 7, "message": cloud.status_code}
                    ),
                },
            }
            lines.append(json.dumps(entry, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"logs/gcp_audit/{project_id}-cloudaudit.jsonl",
                content=content,
                description=(
                    f"GCP Cloud Audit Log export ({len(events)} entries) for project "
                    f"'{project_id}', JSON Lines format."
                ),
            )
        ]
