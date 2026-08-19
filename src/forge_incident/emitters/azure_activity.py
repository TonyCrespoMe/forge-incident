"""Azure Activity Log / Entra ID (Azure AD) audit log emitter.

Renders `Event`s carrying a `cloud` payload as newline-delimited JSON
records approximating an Azure Activity Log / Entra ID audit log entry
(the shape exported via Azure Monitor diagnostic settings or the Entra
`auditLogs`/`signIns` Graph API): `time`, `operationName`, `category`,
`resourceId`, `callerIpAddress`, `identity`, and `resultType`.

As with the other cloud emitters, only the fields the shared
`CloudApiCall` model carries are populated — a representative subset,
not a byte-for-byte Azure schema match.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import (
    EmittedArtifact,
    Emitter,
    iso8601_z_timestamp,
    stable_hex_id,
)
from forge_incident.models import LogSource, Scenario

__all__ = ["AzureActivityEmitter"]


class AzureActivityEmitter(Emitter):
    log_source = LogSource.AZURE_ACTIVITY

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.cloud is not None]
        if not events:
            return []

        subscription_id = (
            scenario.organization.gcp_project_id or "00000000-0000-0000-0000-000000000000"
        )
        lines: list[str] = []

        for event in events:
            cloud = event.cloud
            assert cloud is not None
            principal = scenario.get_actor(event.actor).email if event.actor else "unknown"

            record = {
                "time": iso8601_z_timestamp(event.timestamp),
                "operationId": stable_hex_id(
                    event.event_id, "azure_activity", "operationId", length=36
                ),
                "operationName": cloud.method_name,
                "category": cloud.service_name,
                "resultType": "Success" if cloud.status_code == "OK" else cloud.status_code,
                "resultSignature": cloud.status_code,
                "callerIpAddress": cloud.caller_ip,
                "correlationId": stable_hex_id(
                    event.event_id, "azure_activity", "correlationId", length=36
                ),
                "identity": {
                    "claims": {"upn": principal},
                    "authorization": {"scope": cloud.resource_name},
                },
                "properties": {
                    "resourceId": cloud.resource_name,
                    "userAgent": cloud.user_agent or "python-requests/2.31.0",
                },
                "resourceId": (
                    f"/subscriptions/{subscription_id}/{cloud.resource_name.lstrip('/')}"
                ),
                "subscriptionId": subscription_id,
            }
            lines.append(json.dumps(record, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path=f"logs/azure_activity/{subscription_id}-activity.jsonl",
                content=content,
                description=(
                    f"Azure Activity / Entra ID audit log export ({len(events)} entries) "
                    f"for subscription {subscription_id}, JSON Lines format."
                ),
            )
        ]
