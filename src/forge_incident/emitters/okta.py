"""Okta System Log emitter.

Renders `Event`s tagged `LogSource.OKTA` as newline-delimited JSON shaped
like an Okta System Log export (the `/api/v1/logs` response body, which is
also what Okta's log-streaming integrations forward to a SIEM): `uuid`,
`published`, `eventType`, `outcome`, `actor`, `client`, `authenticationContext`,
`securityContext`, and `target`.

Correlation with the rest of a scenario is automatic and requires nothing
extra from the scenario author. Like every other emitter, this one never
invents an identifier that isn't already on the shared `Event`:

- The **user** comes from `Event.actor` — the same `Identity` the Windows,
  Linux, and cloud emitters resolve, so the username/email in an Okta
  record is identical to the one in every other log the actor appears in.
- The **client IP** is taken from whichever typed payload the event
  already carries, in order: `network.src_ip`, then `cloud.caller_ip`,
  then the event's `host` IP. So an attacker IP that shows up in the
  firewall log shows up byte-identical here, which is exactly the
  cross-source pivot this log source is used to teach.

`Event.description`/`Event.mitre` are instructor-only (see models.py) and
are deliberately never rendered here — `displayMessage` uses Okta's own
canonical message text for the mapped `eventType` instead.
"""

from __future__ import annotations

import json

from forge_incident.emitters.base import (
    EmittedArtifact,
    Emitter,
    gcp_rfc3339,
    humanize_event_type,
    stable_hex_id,
)
from forge_incident.models import Event, EventType, LogSource, Scenario, Severity

__all__ = ["OktaEmitter"]

# Okta eventType + its canonical displayMessage. Only real Okta event types
# are used here; anything unmapped falls back to a generic system event so
# no timeline event is silently dropped.
_EVENT_TYPE_MAP: dict[EventType, tuple[str, str]] = {
    EventType.ACCOUNT_LOGIN_SUCCESS: ("user.session.start", "User login to Okta"),
    EventType.ACCOUNT_LOGIN_FAILURE: ("user.session.start", "User login to Okta"),
    EventType.ACCOUNT_LOCKOUT: ("user.account.lock", "Account locked out"),
    EventType.MFA_CHALLENGE: (
        "user.authentication.auth_via_mfa",
        "Authentication of user via MFA",
    ),
    EventType.MFA_BYPASS: (
        "user.mfa.attempt_bypass",
        "User attempted to bypass MFA",
    ),
    EventType.PASSWORD_RESET: ("user.account.update_password", "User update password"),
    EventType.USER_CREATED: ("user.lifecycle.create", "Create Okta user"),
    EventType.GROUP_MEMBERSHIP_CHANGED: (
        "group.user_membership.add",
        "Add user to group membership",
    ),
    EventType.PRIVILEGE_ESCALATION: (
        "user.account.privilege.grant",
        "Grant user privilege",
    ),
    EventType.CREDENTIAL_HARVESTED: ("user.session.start", "User login to Okta"),
    EventType.ALERT_TRIGGERED: (
        "security.threat.detected",
        "Suspicious activity detected",
    ),
}

_FALLBACK_EVENT_TYPE = "system.operation.executed"

# Okta records outcome per event; failures carry a reason string.
_FAILURE_EVENT_TYPES = {
    EventType.ACCOUNT_LOGIN_FAILURE,
    EventType.MFA_BYPASS,
}

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.INFO: "INFO",
    Severity.LOW: "INFO",
    Severity.MEDIUM: "WARN",
    Severity.HIGH: "WARN",
    Severity.CRITICAL: "ERROR",
}


def _client_ip(event: Event, scenario: Scenario) -> str:
    """Resolve the client IP from whatever the event already carries.

    Deliberately reuses an existing identifier rather than deriving a new
    one, so an IP seen in the firewall/cloud logs is the same string here.
    """
    if event.network is not None:
        return event.network.src_ip
    if event.cloud is not None:
        return event.cloud.caller_ip
    if event.host is not None:
        return scenario.get_host(event.host).ip_address
    return "unknown"


class OktaEmitter(Emitter):
    log_source = LogSource.OKTA

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = self.relevant_events(scenario)
        if not events:
            return []

        org_domain = scenario.organization.domain
        lines: list[str] = []

        for event in events:
            event_type, display_message = _EVENT_TYPE_MAP.get(
                event.event_type,
                (_FALLBACK_EVENT_TYPE, humanize_event_type(event.event_type)),
            )
            succeeded = event.event_type not in _FAILURE_EVENT_TYPES
            actor = scenario.get_actor(event.actor) if event.actor else None
            client_ip = _client_ip(event, scenario)

            record = {
                "uuid": stable_hex_id(event.event_id, "okta", "uuid", length=36),
                "published": gcp_rfc3339(event.timestamp),
                "eventType": event_type,
                "version": "0",
                "displayMessage": display_message,
                "severity": _SEVERITY_MAP[event.severity],
                "legacyEventType": None,
                "actor": {
                    "id": stable_hex_id(
                        actor.username if actor else "unknown", "okta", "actorId", length=20
                    ),
                    "type": "User",
                    "alternateId": actor.email if actor else f"unknown@{org_domain}",
                    "displayName": actor.display_name if actor else "Unknown Actor",
                },
                "client": {
                    "userAgent": {
                        "rawUserAgent": event.extra.get(
                            "user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                        ),
                        "os": "Unknown",
                        "browser": "UNKNOWN",
                    },
                    "zone": "null",
                    "device": "Computer",
                    "ipAddress": client_ip,
                    "ipChain": [{"ip": client_ip}],
                },
                "outcome": {
                    "result": "SUCCESS" if succeeded else "FAILURE",
                    "reason": None if succeeded else "INVALID_CREDENTIALS",
                },
                "authenticationContext": {
                    "authenticationStep": 0,
                    "externalSessionId": stable_hex_id(
                        event.event_id, "okta", "session", length=25
                    ),
                },
                "securityContext": {
                    "asNumber": None,
                    "isProxy": False,
                },
                "target": [
                    {
                        "id": stable_hex_id(org_domain, "okta", "appId", length=20),
                        "type": "AppInstance",
                        "alternateId": event.extra.get("okta_app", org_domain),
                        "displayName": event.extra.get("okta_app", scenario.organization.name),
                    }
                ],
            }
            lines.append(json.dumps(record, separators=(",", ":")))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path="logs/okta/system_log.jsonl",
                content=content,
                description=(
                    f"Okta System Log export ({len(events)} entries), JSON Lines format."
                ),
            )
        ]
