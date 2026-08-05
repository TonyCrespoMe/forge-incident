"""Exchange Online Message Trace emitter.

Renders `Event`s carrying an `email` payload as a CSV approximating the
export you'd get from Exchange Online's Message Trace UI or
`Get-MessageTrace | Export-Csv`: one row per message, covering the fields
students actually need to correlate a delivery against the recovered
.eml and against endpoint telemetry (timestamp, sender/recipient,
subject, status, message size, and the originating client IP).
"""

from __future__ import annotations

import csv
import io

from forge_incident.emitters.base import EmittedArtifact, Emitter, message_trace_timestamp, stable_hex_id
from forge_incident.models import EmailDirection, LogSource, Scenario

__all__ = ["OutlookMessageTraceEmitter"]

_FIELDNAMES = [
    "MessageTraceId",
    "Received (UTC)",
    "SenderAddress",
    "RecipientAddress",
    "Subject",
    "Status",
    "Size (KB)",
    "MessageId",
    "FromIP",
    "Direction",
    "SPF",
    "DKIM",
    "DMARC",
]

# Direction+auth-result heuristic for the Status column. Real Message Trace
# statuses include Delivered/FilteredAsSpam/Failed/Quarantined/Pending;
# ForgeIncident scenarios reaching a user's inbox (the interesting case for
# training) are always "Delivered" — auth failures alone don't guarantee
# filtering, which is itself a useful, realistic teaching point.
_STATUS = "Delivered"


class OutlookMessageTraceEmitter(Emitter):
    log_source = LogSource.OUTLOOK_MESSAGE_TRACE

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.email is not None]
        if not events:
            return []

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_FIELDNAMES, lineterminator="\r\n")
        writer.writeheader()

        for event in events:
            email = event.email
            assert email is not None
            size_kb = round((email.size_bytes or 0) / 1024, 1)
            for recipient in email.recipients:
                writer.writerow(
                    {
                        "MessageTraceId": stable_hex_id(
                            event.event_id, str(recipient), "msgtrace", length=24
                        ),
                        "Received (UTC)": message_trace_timestamp(event.timestamp),
                        "SenderAddress": email.sender,
                        "RecipientAddress": recipient,
                        "Subject": email.subject,
                        "Status": _STATUS,
                        "Size (KB)": size_kb,
                        "MessageId": email.message_id,
                        "FromIP": email.client_ip or "",
                        "Direction": (
                            "Inbound" if email.direction == EmailDirection.INBOUND else
                            "Outbound" if email.direction == EmailDirection.OUTBOUND else
                            "Intraorg"
                        ),
                        "SPF": email.spf.value,
                        "DKIM": email.dkim.value,
                        "DMARC": email.dmarc.value,
                    }
                )

        return [
            EmittedArtifact(
                relative_path="logs/outlook_message_trace/message_trace.csv",
                content=buffer.getvalue(),
                description=(
                    f"Exchange Online Message Trace export ({len(events)} messages), CSV format."
                ),
            )
        ]
