"""Linux syslog/auth-log emitter.

Renders `Event`s tagged `LogSource.LINUX` as RFC 3164-style syslog lines,
one combined per-host log approximating a typical `/var/log/auth.log` /
`/var/log/syslog` blend (auth events via `sshd`, filesystem activity via
a generic audit-style facility, everything else via a `forge-incident`
facility as a documented fallback). Grouped and sorted per host so each
file reads the way a real host's log would.

A single `Event` can expand to *multiple* syslog lines: brute-force style
events set `extra.attempt_count` and this emitter renders that many
consecutive attempts (each with a deterministically-derived port number),
which is what makes the resulting log look like an actual brute-force
burst rather than one suspiciously summarized line.
"""

from __future__ import annotations

from datetime import timedelta

from forge_incident.emitters.base import (
    EmittedArtifact,
    Emitter,
    group_by_host,
    humanize_event_type,
    slugify,
    stable_int_id,
    syslog_timestamp,
)
from forge_incident.models import Event, EventType, LogSource, Scenario

__all__ = ["LinuxEmitter"]

_MAX_RENDERED_ATTEMPTS = 200  # sane ceiling even if a scenario author sets a huge attempt_count


class LinuxEmitter(Emitter):
    log_source = LogSource.LINUX

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = self.relevant_events(scenario)
        if not events:
            return []

        artifacts: list[EmittedArtifact] = []
        for hostname, host_events in group_by_host(events, scenario).items():
            lines: list[str] = []
            for event in host_events:
                lines.extend(self._render_event(event, scenario, hostname))
            artifacts.append(
                EmittedArtifact(
                    relative_path=f"logs/linux/{slugify(hostname)}-syslog.log",
                    content="\n".join(lines) + "\n",
                    description=(
                        f"Linux syslog/auth log for {hostname} ({len(host_events)} events)."
                    ),
                )
            )
        return artifacts

    def _render_event(self, event: Event, scenario: Scenario, hostname: str) -> list[str]:
        username = scenario.get_actor(event.actor).username if event.actor else "unknown"
        ts = syslog_timestamp(event.timestamp)

        if event.event_type in (EventType.ACCOUNT_LOGIN_SUCCESS, EventType.ACCOUNT_LOGIN_FAILURE):
            return self._render_ssh(event, hostname, username, ts)

        if event.event_type in (
            EventType.FILE_CREATED,
            EventType.FILE_MODIFIED,
            EventType.FILE_DELETED,
        ):
            return [self._render_file_op(event, hostname, username, ts)]

        if event.event_type == EventType.PROCESS_CREATED and event.process is not None:
            pid = stable_int_id(event.event_id, "pid", low=1000, high=65000)
            return [
                f"{ts} {hostname} sudo[{pid}]: {username} : COMMAND="
                f"{event.process.command_line}"
            ]

        # Fallback: any other Linux-tagged event still gets rendered, just
        # generically, so an emitter never silently drops an event. Uses a
        # short technical phrase derived from the event type, never
        # `Event.description` — that field is instructor-only narrative
        # (see models.py) and must never leak into student-facing logs.
        pid = stable_int_id(event.event_id, "pid", low=1000, high=65000)
        return [f"{ts} {hostname} forge-incident[{pid}]: {humanize_event_type(event.event_type)}"]

    def _render_ssh(self, event: Event, hostname: str, username: str, ts: str) -> list[str]:
        source_ip = event.extra.get("source_ip") or (
            event.network.src_ip if event.network is not None else "unknown"
        )
        pid = stable_int_id(event.event_id, "sshd_pid", low=1000, high=65000)

        if event.event_type == EventType.ACCOUNT_LOGIN_SUCCESS:
            port = stable_int_id(event.event_id, "port", low=1024, high=65535)
            return [
                f"{ts} {hostname} sshd[{pid}]: Accepted password for {username} "
                f"from {source_ip} port {port} ssh2"
            ]

        attempt_count = min(int(event.extra.get("attempt_count", 1)), _MAX_RENDERED_ATTEMPTS)
        lines = []
        for i in range(attempt_count):
            attempt_pid = pid + i
            port = stable_int_id(event.event_id, "port", str(i), low=1024, high=65535)
            # Spread attempts backward from event.timestamp (2-4s apart,
            # deterministically) so a 47-attempt burst looks like an actual
            # brute-force burst instead of 47 identical-second log lines.
            attempt_ts = event.timestamp - timedelta(
                seconds=sum(
                    stable_int_id(event.event_id, "gap", str(j), low=2, high=4)
                    for j in range(i + 1, attempt_count)
                )
            )
            lines.append(
                f"{syslog_timestamp(attempt_ts)} {hostname} sshd[{attempt_pid}]: Failed password for "
                f"{username} from {source_ip} port {port} ssh2"
            )
        if int(event.extra.get("attempt_count", 1)) > _MAX_RENDERED_ATTEMPTS:
            lines.append(
                f"{ts} {hostname} sshd[{pid}]: "
                f"pam_unix(sshd:auth): message repeated "
                f"{int(event.extra['attempt_count']) - _MAX_RENDERED_ATTEMPTS} times"
            )
        return lines

    def _render_file_op(self, event: Event, hostname: str, username: str, ts: str) -> str:
        pid = stable_int_id(event.event_id, "audit_pid", low=1000, high=65000)
        op = {
            EventType.FILE_CREATED: "PATH_CREATE",
            EventType.FILE_MODIFIED: "PATH_WRITE",
            EventType.FILE_DELETED: "PATH_DELETE",
        }[event.event_type]
        path = event.file.path if event.file is not None else "unknown"
        return (
            f'{ts} {hostname} forge-audit[{pid}]: op={op} uid={username} '
            f'path="{path}" result=success'
        )
