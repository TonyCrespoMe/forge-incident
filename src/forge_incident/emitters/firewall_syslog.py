"""Vendor-neutral firewall syslog emitter (FortiGate-style key=value).

ForgeIncident already ships a PAN-OS emitter (`palo_alto.py`) that renders
a Panorama-style CSV export. This emitter covers the *other* shape
students routinely meet: a firewall streaming `key=value` syslog lines,
here modeled on FortiGate's traffic log format (`date=`, `time=`,
`devname=`, `srcip=`, `dstip=`, `action=`, `sentbyte=`, ...), which is
close enough to the SonicWall/Check Point/Cisco ASA key=value family that
the parsing skills transfer.

Two firewall log sources on the same `Event` timeline is itself a useful
teaching setup: route an event to both `palo_alto` and `firewall_syslog`
and students must reconcile the same session as represented by two
vendors' schemas — the exact "normalize your sources before you correlate"
lesson SIEM engineers need.

Correlation is automatic: every field comes from the shared
`Event.network` payload, so `srcip`/`dstip`/ports/byte counts are
byte-identical to the PAN-OS CSV, the Okta `client.ipAddress`, and the
cloud logs' `callerIp` for the same event.
"""

from __future__ import annotations

import ipaddress

from forge_incident.emitters.base import EmittedArtifact, Emitter, slugify, stable_int_id
from forge_incident.models import LogSource, NetworkAction, Scenario, Severity

__all__ = ["FirewallSyslogEmitter"]

_ACTION_MAP: dict[NetworkAction, str] = {
    NetworkAction.ALLOW: "accept",
    NetworkAction.DENY: "deny",
    NetworkAction.DROP: "deny",
    NetworkAction.RESET: "reset",
}

_LEVEL_MAP: dict[Severity, str] = {
    Severity.INFO: "notice",
    Severity.LOW: "notice",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "warning",
    Severity.CRITICAL: "alert",
}

_PROTOCOL_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _interface_for(ip: str) -> str:
    """FortiGate names the ingress/egress interface per zone; internal
    traffic leaves via `port1` (LAN) and external via `wan1`."""
    return "port1" if _is_private(ip) else "wan1"


def _quote(value: str) -> str:
    """FortiGate quotes string values that may contain spaces."""
    return '"' + str(value).replace('"', "'") + '"'


class FirewallSyslogEmitter(Emitter):
    log_source = LogSource.FIREWALL_SYSLOG

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.network is not None]
        if not events:
            return []

        device_name = f"FW-{slugify(scenario.organization.name, max_length=12).upper()}"
        device_id = f"FGT{stable_int_id(scenario.scenario_id, 'fw', 'serial', low=10**9, high=10**10 - 1)}"

        lines: list[str] = []
        for event in events:
            net = event.network
            assert net is not None  # filtered above; narrows type for readers

            sent = net.bytes_sent or 0
            received = net.bytes_received or 0
            fields = [
                f"date={event.timestamp.strftime('%Y-%m-%d')}",
                f"time={event.timestamp.strftime('%H:%M:%S')}",
                f"devname={_quote(device_name)}",
                f"devid={_quote(device_id)}",
                f"eventtime={int(event.timestamp.timestamp() * 1_000_000_000)}",
                "type=traffic",
                "subtype=forward",
                f"level={_LEVEL_MAP[event.severity]}",
                "vd=root",
                f"srcip={net.src_ip}",
                f"srcport={net.src_port}",
                f"srcintf={_quote(_interface_for(net.src_ip))}",
                f"dstip={net.dst_ip}",
                f"dstport={net.dst_port}",
                f"dstintf={_quote(_interface_for(net.dst_ip))}",
                f"sessionid={stable_int_id(event.event_id, 'fw', 'session', low=1, high=9_999_999)}",
                f"proto={_PROTOCOL_NUMBER.get(net.protocol.value, 0)}",
                f"action={_ACTION_MAP[net.action]}",
                f"policyid={stable_int_id(net.rule_name or 'default', 'fw', 'policy', low=1, high=99)}",
                f"policyname={_quote(net.rule_name or 'default')}",
                f"service={_quote((net.app or 'unknown').upper())}",
                f"appcat={_quote('unscanned')}",
                f"sentbyte={sent}",
                f"rcvdbyte={received}",
                f"sentpkt={max(1, sent // 512)}",
                f"rcvdpkt={max(1, received // 512)}",
                f"duration={stable_int_id(event.event_id, 'fw', 'duration', low=1, high=600)}",
            ]
            lines.append(" ".join(fields))

        content = "\n".join(lines) + "\n"
        return [
            EmittedArtifact(
                relative_path="logs/firewall_syslog/traffic.log",
                content=content,
                description=(
                    f"Firewall traffic syslog ({len(events)} sessions), FortiGate-style "
                    "key=value format."
                ),
            )
        ]
