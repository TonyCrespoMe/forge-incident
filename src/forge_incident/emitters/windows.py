"""Windows Event Log emitter.

Renders `Event`s tagged `LogSource.WINDOWS` as XML records shaped like
what Event Viewer produces via "Save All Events As..." — a sequence of
`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">`
elements (wrapped here in a single `<Events>` root so the file is valid,
parseable XML; a real multi-event export is a bare concatenation of
`<Event>` elements without a shared root, which some tools tolerate and
others don't — wrapping is the more broadly compatible choice).

Each `Event.event_type` maps to a plausible native Windows Event ID and
provider: Security-log IDs (4624/4625/4698/...) for identity/auth/
persistence events, and Sysmon IDs (1/3/11/13) for process, network, and
file telemetry — the two providers instructors most commonly teach
correlation across. One XML file is produced per host.

IMPORTANT: `Event.description` and `Event.mitre` are instructor-facing
narrative fields (see models.py) and are deliberately never written into
rendered output here — that would hand the student the analytic
conclusion inside their own evidence file. Where a record needs a human-
readable "Message" and carries no typed payload, this emitter uses the
real, canonical text Windows itself logs for that Event ID.
"""

from __future__ import annotations

from dataclasses import dataclass

from forge_incident.emitters.base import (
    EmittedArtifact,
    Emitter,
    group_by_host,
    humanize_event_type,
    slugify,
    stable_int_id,
    windows_xml_timestamp,
)
from forge_incident.models import Event, EventType, LogSource, Scenario

__all__ = ["WindowsEmitter"]


@dataclass(frozen=True)
class _EventIdMapping:
    channel: str
    provider: str
    event_id: int
    level: str  # Windows Level: 1=Critical 2=Error 3=Warning 4=Information
    # The real, canonical message Windows/Sysmon logs for this Event ID.
    # Used only as a Message fallback for records with no typed payload —
    # never `Event.description`, which is instructor-only narrative.
    message: str = ""


_MAPPING: dict[EventType, _EventIdMapping] = {
    EventType.ACCOUNT_LOGIN_SUCCESS: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4624, "4", "An account was successfully logged on."),
    EventType.ACCOUNT_LOGIN_FAILURE: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4625, "4", "An account failed to log on."),
    EventType.ACCOUNT_LOCKOUT: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4740, "4", "A user account was locked out."),
    EventType.USER_CREATED: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4720, "4", "A user account was created."),
    EventType.GROUP_MEMBERSHIP_CHANGED: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4728, "4", "A member was added to a security-enabled global group."),
    EventType.PRIVILEGE_ESCALATION: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4672, "4", "Special privileges assigned to new logon."),
    EventType.PERSISTENCE_ESTABLISHED: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4698, "4", "A scheduled task was created."),
    EventType.SCHEDULED_TASK_CREATED: _EventIdMapping("Security", "Microsoft-Windows-Security-Auditing", 4698, "4", "A scheduled task was created."),
    EventType.ATTACHMENT_OPENED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, "4", "Process Create"),
    EventType.PROCESS_CREATED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, "4", "Process Create"),
    EventType.MALWARE_EXECUTION: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, "2", "Process Create"),
    EventType.PROCESS_INJECTION: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 8, "2", "CreateRemoteThread detected"),
    EventType.LATERAL_MOVEMENT: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "3", "Network connection detected"),
    EventType.C2_BEACON: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "3", "Network connection detected"),
    EventType.NETWORK_CONNECTION_ALLOWED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "4", "Network connection detected"),
    EventType.NETWORK_CONNECTION_BLOCKED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "3", "Network connection detected"),
    EventType.FILE_CREATED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 11, "4", "File create detected"),
    EventType.DATA_STAGING: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 11, "3", "File create detected"),
    EventType.REGISTRY_MODIFIED: _EventIdMapping("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 13, "4", "Registry value set"),
    EventType.ALERT_TRIGGERED: _EventIdMapping("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, "2", "Windows Defender Antivirus has detected malware or other potentially unwanted software."),
    # 7045 is the System-log signature left by PsExec-style remote execution
    # (Invoke-SMBExec, Impacket smbexec): one throwaway service per remote
    # command, ImagePath carrying the command itself. See models.ServiceInstall.
    EventType.SERVICE_INSTALLED: _EventIdMapping("System", "Service Control Manager", 7045, "4", "A service was installed in the system."),
}

# Any EventType not in _MAPPING (or with a native EVTX channel this project
# doesn't otherwise model) still gets rendered here so no event is silently
# dropped.
_FALLBACK = _EventIdMapping("Application", "ForgeIncident", 9999, "4", "")


class WindowsEmitter(Emitter):
    log_source = LogSource.WINDOWS

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = self.relevant_events(scenario)
        if not events:
            return []

        artifacts: list[EmittedArtifact] = []
        for hostname, host_events in group_by_host(events, scenario).items():
            records = [self._render_event(e, scenario, hostname) for e in host_events]
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<Events>\n" + "\n".join(records) + "\n</Events>\n"
            )
            artifacts.append(
                EmittedArtifact(
                    relative_path=f"logs/windows/{slugify(hostname)}-events.xml",
                    content=xml,
                    description=f"Windows Event Log export for {hostname} ({len(host_events)} events).",
                )
            )
        return artifacts

    def _render_event(self, event: Event, scenario: Scenario, hostname: str) -> str:
        # A `service` payload means Windows physically wrote a 7045 record,
        # whatever the analyst later classifies the event as. A scenario can
        # legitimately call a service-install `malware_execution` (that IS what
        # happened), but the log line Windows produced is still 7045 -- so the
        # payload wins over the event_type when choosing the record shape.
        if event.service is not None:
            mapping = _MAPPING[EventType.SERVICE_INSTALLED]
        else:
            mapping = _MAPPING.get(event.event_type, _FALLBACK)
        record_id = stable_int_id(event.event_id, "record_id", low=1, high=2_000_000_000)
        username = scenario.get_actor(event.actor).username if event.actor else None
        domain = scenario.organization.domain

        event_data_items: list[str] = []
        if event.process is not None:
            p = event.process
            event_data_items += [
                _data("ProcessId", str(p.pid)),
                _data("Image", p.name),
                _data("CommandLine", p.command_line),
                _data("ParentProcessId", str(p.ppid) if p.ppid is not None else ""),
                _data("ParentImage", p.parent_name or ""),
                _data("Hashes", f"SHA256={p.sha256}" if p.sha256 else ""),
                _data("IntegrityLevel", p.integrity_level or ""),
            ]
        if event.service is not None:
            s = event.service
            event_data_items += [
                _data("ServiceName", s.service_name),
                _data("ImagePath", s.image_path),
                _data("ServiceType", s.service_type),
                _data("StartType", s.start_type),
                _data("AccountName", s.account),
            ]
        if event.network is not None:
            n = event.network
            event_data_items += [
                _data("SourceIp", n.src_ip),
                _data("SourcePort", str(n.src_port)),
                _data("DestinationIp", n.dst_ip),
                _data("DestinationPort", str(n.dst_port)),
                _data("Protocol", n.protocol.value),
            ]
        if event.file is not None:
            f = event.file
            event_data_items += [
                _data("TargetFilename", f.path),
                _data("Hashes", f"SHA256={f.sha256}" if f.sha256 else ""),
            ]
        if not event_data_items:
            # Security-log-style events (logons, user/group changes,
            # scheduled tasks) that carry no typed payload still get a
            # human-readable message — the real canonical Windows text for
            # this Event ID, never Event.description (instructor-only).
            message = mapping.message or humanize_event_type(event.event_type)
            event_data_items.append(_data("Message", message))
        if username:
            event_data_items.append(_data("TargetUserName", username))
            event_data_items.append(_data("TargetDomainName", domain))

        return f"""  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="{_esc(mapping.provider)}"/>
      <EventID>{mapping.event_id}</EventID>
      <Level>{mapping.level}</Level>
      <TimeCreated SystemTime="{windows_xml_timestamp(event.timestamp)}"/>
      <EventRecordID>{record_id}</EventRecordID>
      <Channel>{_esc(mapping.channel)}</Channel>
      <Computer>{_esc(hostname)}</Computer>
      <Security UserID="{_esc(username or 'S-1-5-18')}"/>
    </System>
    <EventData>
{chr(10).join('      ' + item for item in event_data_items)}
    </EventData>
  </Event>"""


def _data(name: str, value: str) -> str:
    return f'<Data Name="{_esc(name)}">{_esc(value)}</Data>'


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
