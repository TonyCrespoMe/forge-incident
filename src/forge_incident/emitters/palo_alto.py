"""Palo Alto Networks (PAN-OS) traffic log emitter.

Renders `Event`s carrying a `network` payload as a CSV using a
representative subset (in the standard field order) of a PAN-OS traffic
log export — the same log type instructors typically pull from Panorama
or the firewall's own "Monitor > Traffic" CSV export. Only TRAFFIC-type
"end of session" summary rows are produced; ForgeIncident does not model
individual packets.
"""

from __future__ import annotations

import csv
import io
import ipaddress

from forge_incident.emitters.base import EmittedArtifact, Emitter, pan_os_timestamp, stable_int_id
from forge_incident.models import LogSource, NetworkAction, Scenario

__all__ = ["PaloAltoEmitter"]

_FIELDNAMES = [
    "Receive Time",
    "Serial Number",
    "Type",
    "Subtype",
    "Generate Time",
    "Source address",
    "Destination address",
    "Rule Name",
    "Application",
    "Virtual System",
    "Source Zone",
    "Destination Zone",
    "Session ID",
    "Repeat Count",
    "Source Port",
    "Destination Port",
    "IP Protocol",
    "Action",
    "Bytes",
    "Bytes Sent",
    "Bytes Received",
    "Packets",
    "Start Time",
    "Elapsed Time (sec)",
    "Category",
]

_ACTION_MAP = {
    NetworkAction.ALLOW: "allow",
    NetworkAction.DENY: "deny",
    NetworkAction.DROP: "drop",
    NetworkAction.RESET: "reset-both",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _zone_for(ip: str) -> str:
    return "trust" if _is_private(ip) else "untrust"


class PaloAltoEmitter(Emitter):
    log_source = LogSource.PALO_ALTO

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.network is not None]
        if not events:
            return []

        serial_number = stable_int_id(
            scenario.scenario_id, "pan_os", "serial", low=10 ** 14, high=10 ** 15 - 1
        )

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_FIELDNAMES, lineterminator="\r\n")
        writer.writeheader()

        for event in events:
            net = event.network
            assert net is not None
            receive_time = pan_os_timestamp(event.timestamp)
            elapsed = stable_int_id(event.event_id, "elapsed", low=1, high=6)
            packets = max(1, (net.bytes_sent or 0) // 512 + (net.bytes_received or 0) // 512)

            writer.writerow(
                {
                    "Receive Time": receive_time,
                    "Serial Number": str(serial_number),
                    "Type": "TRAFFIC",
                    "Subtype": "end",
                    "Generate Time": receive_time,
                    "Source address": net.src_ip,
                    "Destination address": net.dst_ip,
                    "Rule Name": net.rule_name or (
                        "default-allow" if net.action == NetworkAction.ALLOW else "default-deny"
                    ),
                    "Application": net.app or "unknown",
                    "Virtual System": "vsys1",
                    "Source Zone": _zone_for(net.src_ip),
                    "Destination Zone": _zone_for(net.dst_ip),
                    "Session ID": stable_int_id(event.event_id, "session", low=1, high=999_999),
                    "Repeat Count": 1,
                    "Source Port": net.src_port,
                    "Destination Port": net.dst_port,
                    "IP Protocol": net.protocol.value,
                    "Action": _ACTION_MAP[net.action],
                    "Bytes": (net.bytes_sent or 0) + (net.bytes_received or 0),
                    "Bytes Sent": net.bytes_sent or 0,
                    "Bytes Received": net.bytes_received or 0,
                    "Packets": packets,
                    "Start Time": receive_time,
                    "Elapsed Time (sec)": elapsed,
                    "Category": "any",
                }
            )

        return [
            EmittedArtifact(
                relative_path="logs/palo_alto/traffic.csv",
                content=buffer.getvalue(),
                description=f"PAN-OS traffic log export ({len(events)} sessions), CSV format.",
            )
        ]
