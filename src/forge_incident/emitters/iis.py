"""Microsoft IIS W3C Extended Log Format emitter.

Renders `Event`s carrying an `http` payload as an IIS access log — the
`u_exYYMMDDHH.log` files under `C:\\inetpub\\logs\\LogFiles\\W3SVC1\\`, in
the default W3C extended field set most IIS deployments ship with.

Three details here are deliberate, because they are what make the output
behave like a *real* IIS log rather than a clean CSV:

1. **Space-separated with `-` for empty fields.** W3C extended format uses
   a single space as the delimiter and a bare hyphen for "no value". It is
   not quoted CSV. Naive `awk '{print $9}'` parsing therefore breaks the
   moment any field is absent, which is an authentic and worth-teaching
   frustration — real analysts hit exactly this.
2. **User agents have spaces replaced with `+`.** IIS does this natively
   (`Mozilla/5.0+(Windows+NT+10.0...`), and it trips up anyone who assumes
   they can split on whitespace. Reproduced faithfully.
3. **POST bodies are not logged.** IIS records `cs-uri-query` but never
   the request body. A scenario can therefore route a web-shell command
   through a POST and the command is genuinely absent from this log — the
   student has to prove it happened from the target host's telemetry.
   That visibility gap is a first-class teaching device, not a modeling
   shortcut (see `models.HttpRequest`).
4. **`sc-bytes` (response size) is included.** Not part of the bare
   minimum W3C set, but a very commonly enabled one — real security teams
   lean on it constantly, because an endpoint's response size is often the
   loudest, least ambiguous signal that something abnormal happened,
   independent of status code. `HttpRequest.bytes_sent` renders here as
   `0` when unset. See the bundled `sql_injection_data_breach.yaml`,
   where a single-record lookup endpoint suddenly returning megabytes is
   the scenario's central tell.

Web-shell commands supplied as `http.cmd_plaintext` are **base64-encoded**
into the query string here, matching how this class of shell is actually
operated, so students must recognize and decode the encoding rather than
reading the attack in cleartext.
"""

from __future__ import annotations

import base64
from datetime import datetime

from forge_incident.emitters.base import EmittedArtifact, Emitter
from forge_incident.models import Event, LogSource, Scenario

__all__ = ["IisEmitter"]

#: The default W3C extended field set for IIS 10, in order.
_FIELDS = (
    "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
    "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken sc-bytes"
)

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
)


def _iis_field(value: object | None) -> str:
    """Render one field: `-` for absent, spaces escaped as `+` like IIS does."""
    if value is None or value == "":
        return "-"
    return str(value).replace(" ", "+")


def _build_query(http, event_id: str) -> str | None:
    """The effective query string, base64-encoding a web-shell command if present.

    A command is only smuggled through the query string on GET-style
    requests; on a POST it would live in the body, which IIS does not log
    — so we deliberately return the declared query (often nothing) and let
    the command vanish, exactly as it would in production.
    """
    if http.cmd_plaintext and http.method.upper() != "POST":
        encoded = base64.b64encode(http.cmd_plaintext.encode("utf-8")).decode("ascii")
        pair = f"{http.cmd_param}={encoded}"
        return f"{http.uri_query}&{pair}" if http.uri_query else pair
    return http.uri_query


def _client_ip(event: Event, scenario: Scenario) -> str:
    """Who made the request. Prefers an explicit network source, then the host."""
    if event.network is not None:
        return event.network.src_ip
    if event.host is not None:
        return scenario.get_host(event.host).ip_address
    return "-"


class IisEmitter(Emitter):
    log_source = LogSource.IIS

    def emit(self, scenario: Scenario) -> list[EmittedArtifact]:
        events = [e for e in self.relevant_events(scenario) if e.http is not None]
        if not events:
            return []

        first = events[0].timestamp
        server_ip = next(
            (e.http.server_ip for e in events if e.http and e.http.server_ip),
            None,
        )
        if server_ip is None:
            # Fall back to whichever host serves these requests.
            hosted = next((e.host for e in events if e.host), None)
            server_ip = scenario.get_host(hosted).ip_address if hosted else "127.0.0.1"

        lines = [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Version: 1.0",
            f"#Date: {first.strftime('%Y-%m-%d %H:%M:%S')}",
            f"#Fields: {_FIELDS}",
        ]

        for event in events:
            http = event.http
            assert http is not None  # filtered above; narrows type for readers
            actor = scenario.get_actor(event.actor) if event.actor else None

            lines.append(
                " ".join(
                    (
                        event.timestamp.strftime("%Y-%m-%d"),
                        event.timestamp.strftime("%H:%M:%S"),
                        _iis_field(http.server_ip or server_ip),
                        _iis_field(http.method.upper()),
                        _iis_field(http.uri_stem),
                        _iis_field(_build_query(http, event.event_id)),
                        _iis_field(http.server_port),
                        _iis_field(http.username or (actor.username if actor else None)),
                        _iis_field(_client_ip(event, scenario)),
                        _iis_field(http.user_agent or _DEFAULT_UA),
                        _iis_field(http.referer),
                        _iis_field(http.status_code),
                        _iis_field(http.substatus),
                        _iis_field(http.win32_status),
                        _iis_field(http.time_taken_ms if http.time_taken_ms is not None else 0),
                        _iis_field(http.bytes_sent if http.bytes_sent is not None else 0),
                    )
                )
            )

        filename = _log_filename(first)
        return [
            EmittedArtifact(
                relative_path=f"logs/iis/{filename}",
                content="\n".join(lines) + "\n",
                description=(
                    f"IIS W3C extended access log ({len(events)} requests), "
                    "space-delimited with '-' for empty fields."
                ),
            )
        ]


def _log_filename(when: datetime) -> str:
    """IIS names hourly logs `u_exYYMMDDHH.log` — e.g. 2025-03-09 09:xx -> u_ex25030909.log."""
    return f"u_ex{when.strftime('%y%m%d%H')}.log"
