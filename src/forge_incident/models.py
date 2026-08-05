"""Central data model for ForgeIncident.

Every scenario, every emitted log line, and every artifact in a generated
package is derived from the structures in this module. This is the single
source of truth: a `Scenario` holds an `Identity`/`Host` registry and an
ordered `Event` timeline, and every emitter (GCP Audit, Message Trace,
Palo Alto, Linux, Windows, .eml) reads from the *same* `Event` objects.
Because nothing downstream invents its own timestamps, IPs, usernames,
PIDs, or hashes, identifiers stay perfectly consistent across every file
in a generated investigation package.

Nothing in this module performs I/O, randomness, or LLM calls. Construction
of `Scenario`/`Event` objects (whether from YAML or from an LLM-assisted
natural-language plan) always goes through `scenario_loader`, which is
responsible for determinism (seeding) and validation.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------
# Shared regex patterns
# --------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ForgeBaseModel(BaseModel):
    """Base class shared by every model in ForgeIncident.

    `extra="forbid"` catches typos in hand-written YAML scenarios early
    (scenario_loader surfaces these as friendly validation errors rather
    than silently dropping fields). `frozen=False` because scenario_loader
    may progressively fill in defaults (e.g. deterministic IDs) after
    initial construction.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Difficulty(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class HostType(str, Enum):
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    SERVER = "server"
    CLOUD_INSTANCE = "cloud_instance"
    DOMAIN_CONTROLLER = "domain_controller"


class OperatingSystem(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD = "cloud"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class NetworkAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    RESET = "reset"


class EmailDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NONE = "none"


class LogSource(str, Enum):
    """Which emitter(s) a given Event should be rendered by.

    A single Event may be relevant to more than one emitter (e.g. a
    phishing click is both an `EMAIL_EML` artifact and a `PALO_ALTO`
    network hit); `Event.log_sources` is therefore a list.
    """

    GCP_AUDIT = "gcp_audit"
    OUTLOOK_MESSAGE_TRACE = "outlook_message_trace"
    PALO_ALTO = "palo_alto"
    LINUX = "linux"
    WINDOWS = "windows"
    EMAIL_EML = "email_eml"


class EventType(str, Enum):
    # --- Identity / auth ---
    ACCOUNT_LOGIN_SUCCESS = "account_login_success"
    ACCOUNT_LOGIN_FAILURE = "account_login_failure"
    ACCOUNT_LOCKOUT = "account_lockout"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_BYPASS = "mfa_bypass"
    PASSWORD_RESET = "password_reset"
    USER_CREATED = "user_created"
    GROUP_MEMBERSHIP_CHANGED = "group_membership_changed"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # --- Email / phishing ---
    PHISHING_EMAIL_DELIVERED = "phishing_email_delivered"
    PHISHING_EMAIL_CLICKED = "phishing_email_clicked"
    ATTACHMENT_OPENED = "attachment_opened"
    CREDENTIAL_HARVESTED = "credential_harvested"
    EMAIL_SENT = "email_sent"
    EMAIL_FORWARDING_RULE_CREATED = "email_forwarding_rule_created"

    # --- Endpoint / malware ---
    MALWARE_DOWNLOAD = "malware_download"
    MALWARE_EXECUTION = "malware_execution"
    PROCESS_CREATED = "process_created"
    PROCESS_INJECTION = "process_injection"
    PERSISTENCE_ESTABLISHED = "persistence_established"
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    REGISTRY_MODIFIED = "registry_modified"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"

    # --- Network ---
    DNS_QUERY = "dns_query"
    NETWORK_CONNECTION_ALLOWED = "network_connection_allowed"
    NETWORK_CONNECTION_BLOCKED = "network_connection_blocked"
    C2_BEACON = "c2_beacon"
    LATERAL_MOVEMENT = "lateral_movement"

    # --- Exfil / impact ---
    DATA_STAGING = "data_staging"
    DATA_EXFILTRATION = "data_exfiltration"
    LOG_CLEARED = "log_cleared"
    RANSOMWARE_ENCRYPTION = "ransomware_encryption"

    # --- Cloud ---
    CLOUD_API_CALL = "cloud_api_call"
    CLOUD_PERMISSION_CHANGE = "cloud_permission_change"
    CLOUD_RESOURCE_CREATED = "cloud_resource_created"
    CLOUD_RESOURCE_DELETED = "cloud_resource_deleted"

    # --- Detection ---
    ALERT_TRIGGERED = "alert_triggered"


# --------------------------------------------------------------------------
# Shared value objects
# --------------------------------------------------------------------------


class MitreTechnique(ForgeBaseModel):
    """A single ATT&CK technique reference attached to an Event."""

    technique_id: str = Field(..., description="e.g. 'T1566.001'")
    technique_name: str = Field(..., description="e.g. 'Spearphishing Attachment'")
    tactic: str = Field(..., description="e.g. 'Initial Access'")

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, v: str) -> str:
        if not _MITRE_TECHNIQUE_RE.match(v):
            raise ValueError(f"'{v}' is not a valid MITRE ATT&CK technique ID (e.g. T1566.001)")
        return v


class OrgProfile(ForgeBaseModel):
    """The fictional organization the scenario takes place in."""

    name: str
    domain: str = Field(..., description="Email/corporate domain, e.g. 'globex.example'")
    industry: str | None = None
    timezone: str = "UTC"
    gcp_project_id: str | None = Field(
        default=None, description="Used by the gcp_audit emitter as resource.labels.project_id"
    )


class Identity(ForgeBaseModel):
    """A human or service account referenced by Events via `Event.actor`.

    `Scenario.actors` maps a short local key (e.g. 'victim', 'attacker')
    to one of these; emitters resolve the key back to this object so that
    username/email/display_name are always consistent everywhere.
    """

    username: str = Field(..., description="e.g. 'jdoe' — used in Linux/Windows logs")
    email: EmailStr
    display_name: str
    department: str | None = None
    role_title: str | None = None
    employee_id: str | None = None
    is_compromised: bool = False
    is_privileged: bool = False


class Host(ForgeBaseModel):
    """A machine referenced by Events via `Event.host`."""

    hostname: str
    ip_address: str = Field(..., description="IPv4/IPv6 literal")
    host_type: HostType = HostType.WORKSTATION
    os: OperatingSystem = OperatingSystem.WINDOWS
    os_version: str | None = None
    mac_address: str | None = None
    domain_joined: bool = True

    @field_validator("mac_address")
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        if v is not None and not _MAC_RE.match(v):
            raise ValueError(f"'{v}' is not a valid MAC address (aa:bb:cc:dd:ee:ff)")
        return v


class ProcessInfo(ForgeBaseModel):
    """Process-creation details for Windows Sysmon / Linux auditd style events."""

    pid: int = Field(..., ge=1)
    ppid: int | None = Field(default=None, ge=1)
    name: str = Field(..., description="e.g. 'powershell.exe' or 'bash'")
    command_line: str
    parent_name: str | None = None
    sha256: str | None = None
    integrity_level: str | None = Field(
        default=None, description="Windows only, e.g. 'High', 'System'"
    )

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_RE.match(v):
            raise ValueError(f"'{v}' is not a valid sha256 hex digest")
        return v


class FileInfo(ForgeBaseModel):
    """A file artifact referenced by an Event (download, drop, exfil, etc.)."""

    path: str
    filename: str
    sha256: str | None = None
    md5: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_RE.match(v):
            raise ValueError(f"'{v}' is not a valid sha256 hex digest")
        return v

    @field_validator("md5")
    @classmethod
    def _validate_md5(cls, v: str | None) -> str | None:
        if v is not None and not _MD5_RE.match(v):
            raise ValueError(f"'{v}' is not a valid md5 hex digest")
        return v


class EmailArtifact(ForgeBaseModel):
    """Feeds both the outlook_message_trace and email_eml emitters."""

    message_id: str = Field(..., description="RFC 5322 style, e.g. '<uuid@globex.example>'")
    sender: EmailStr
    recipients: list[EmailStr] = Field(..., min_length=1)
    subject: str
    direction: EmailDirection = EmailDirection.INBOUND
    spf: AuthResult = AuthResult.NONE
    dkim: AuthResult = AuthResult.NONE
    dmarc: AuthResult = AuthResult.NONE
    has_attachment: bool = False
    attachment_name: str | None = None
    attachment_sha256: str | None = None
    body_text: str | None = None
    client_ip: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)

    @field_validator("attachment_sha256")
    @classmethod
    def _validate_sha256(cls, v: str | None) -> str | None:
        if v is not None and not _SHA256_RE.match(v):
            raise ValueError(f"'{v}' is not a valid sha256 hex digest")
        return v

    @model_validator(mode="after")
    def _attachment_consistency(self) -> "EmailArtifact":
        if self.has_attachment and not self.attachment_name:
            raise ValueError("has_attachment=True requires attachment_name to be set")
        return self


class NetworkInfo(ForgeBaseModel):
    """Feeds the palo_alto (and optionally linux/windows firewall) emitters."""

    protocol: Protocol = Protocol.TCP
    src_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(..., ge=0, le=65535)
    action: NetworkAction = NetworkAction.ALLOW
    app: str | None = Field(default=None, description="Palo Alto App-ID, e.g. 'ssl', 'dns-base'")
    rule_name: str | None = None
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)


class CloudApiCall(ForgeBaseModel):
    """Feeds the gcp_audit emitter."""

    method_name: str = Field(
        ..., description="e.g. 'google.iam.admin.v1.CreateServiceAccountKey'"
    )
    service_name: str = Field(..., description="e.g. 'iam.googleapis.com'")
    resource_name: str
    caller_ip: str
    user_agent: str | None = None
    status_code: str = Field(default="OK", description="'OK', 'PERMISSION_DENIED', etc.")
    project_id: str | None = None


# --------------------------------------------------------------------------
# Event: the atomic, shared unit of truth
# --------------------------------------------------------------------------


class Event(ForgeBaseModel):
    """One thing that happened, at one time, to one actor/host.

    A `Scenario.timeline` is an ordered list of these. Each emitter filters
    the timeline down to events whose `log_sources` include it, then
    renders each Event's typed payload (`process`, `email`, `network`,
    `cloud`, `file`) into its own log format. Because every emitter reads
    the same Event objects, an attacker's IP, PID, or file hash is
    identical whether you're looking at the Palo Alto log or the Windows
    Sysmon log.
    """

    event_id: str = Field(
        ..., description="Deterministic ID, typically uuid5(scenario_seed, index)"
    )
    index: int = Field(..., ge=0, description="Position in the scenario timeline")
    timestamp: datetime
    event_type: EventType
    log_sources: list[LogSource] = Field(..., min_length=1)
    severity: Severity = Severity.INFO

    actor: str | None = Field(
        default=None, description="Key into Scenario.actors, e.g. 'victim'"
    )
    host: str | None = Field(default=None, description="Key into Scenario.hosts, e.g. 'ws-01'")

    description: str = Field(..., description="Human-readable summary for instructor materials")
    mitre: MitreTechnique | None = None

    # Typed, emitter-specific payloads. Exactly the ones relevant to this
    # event's log_sources should be populated; scenario_loader validates
    # that each declared log_source has the payload it needs.
    process: ProcessInfo | None = None
    email: EmailArtifact | None = None
    network: NetworkInfo | None = None
    cloud: CloudApiCall | None = None
    file: FileInfo | None = None

    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Escape hatch for emitter-specific fields not worth modeling formally",
    )

    @field_validator("timestamp")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Event.timestamp must be timezone-aware (use UTC)")
        return v


# --------------------------------------------------------------------------
# Answer key / instructor materials
# --------------------------------------------------------------------------


class AnswerKeyItem(ForgeBaseModel):
    """One instructor-facing question tied back to specific timeline events."""

    id: str
    question: str
    answer: str
    related_event_ids: list[str] = Field(default_factory=list)
    hint: str | None = None
    points: int = Field(default=1, ge=0)


# --------------------------------------------------------------------------
# Scenario: the top-level container
# --------------------------------------------------------------------------


class Scenario(ForgeBaseModel):
    """A complete, self-contained investigation scenario.

    This is what `scenario_loader.load()` produces from a YAML file (or
    what an LLM-assisted natural-language plan is normalized into before
    generation). Everything downstream — emitters and the packager — only
    ever consumes a `Scenario`.
    """

    scenario_id: str = Field(..., description="Stable slug, e.g. 'phishing-to-exfil-01'")
    title: str
    description: str = Field(
        ...,
        description=(
            "Full, spoiler-ful instructor-facing summary of the attack narrative. "
            "Goes in instructor materials only — see `student_briefing` for what "
            "students are shown."
        ),
    )
    student_briefing: str = Field(
        ...,
        description=(
            "The non-spoiler prompt shown to students in their package README. "
            "Should scope the investigation (who/what/which logs) the way a real "
            "engagement kickoff would, WITHOUT revealing the attack chain, "
            "technique names, or which host/account turns out to be compromised "
            "beyond what a real incident report would already state."
        ),
    )
    difficulty: Difficulty = Difficulty.INTERMEDIATE
    version: str = "1.0"

    seed: int = Field(..., ge=0, description="Master seed; guarantees reproducible generation")
    organization: OrgProfile

    mitre_tactics: list[str] = Field(default_factory=list)
    learning_objectives: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    actors: dict[str, Identity] = Field(..., min_length=1)
    hosts: dict[str, Host] = Field(default_factory=dict)

    timeline: list[Event] = Field(..., min_length=1)
    answer_key: list[AnswerKeyItem] = Field(default_factory=list)

    # -- Cross-field validation -------------------------------------------------

    @model_validator(mode="after")
    def _validate_references(self) -> "Scenario":
        actor_keys = set(self.actors)
        host_keys = set(self.hosts)
        event_ids = set()

        for event in self.timeline:
            if event.actor is not None and event.actor not in actor_keys:
                raise ValueError(
                    f"Event {event.event_id!r} references unknown actor {event.actor!r}; "
                    f"known actors: {sorted(actor_keys)}"
                )
            if event.host is not None and event.host not in host_keys:
                raise ValueError(
                    f"Event {event.event_id!r} references unknown host {event.host!r}; "
                    f"known hosts: {sorted(host_keys)}"
                )
            if event.event_id in event_ids:
                raise ValueError(f"Duplicate event_id detected: {event.event_id!r}")
            event_ids.add(event.event_id)

        for item in self.answer_key:
            unknown = set(item.related_event_ids) - event_ids
            if unknown:
                raise ValueError(
                    f"Answer key item {item.id!r} references unknown event_ids: {sorted(unknown)}"
                )

        # Timeline must be chronologically non-decreasing so emitters can
        # assume ordered input without re-sorting (and so diffing/log
        # tailing "feels" realistic).
        timestamps = [e.timestamp for e in self.timeline]
        if timestamps != sorted(timestamps):
            raise ValueError("Scenario.timeline must be sorted by timestamp, ascending")

        return self

    # -- Convenience accessors ---------------------------------------------------

    def get_actor(self, key: str) -> Identity:
        try:
            return self.actors[key]
        except KeyError as exc:
            raise KeyError(f"No actor registered under key {key!r}") from exc

    def get_host(self, key: str) -> Host:
        try:
            return self.hosts[key]
        except KeyError as exc:
            raise KeyError(f"No host registered under key {key!r}") from exc

    def events_for(self, log_source: LogSource) -> list[Event]:
        """All timeline events relevant to a given emitter, in order."""
        return [e for e in self.timeline if log_source in e.log_sources]

    @property
    def start_time(self) -> datetime:
        return self.timeline[0].timestamp

    @property
    def end_time(self) -> datetime:
        return self.timeline[-1].timestamp

    @property
    def duration(self) -> timedelta:
        return self.end_time - self.start_time

    @property
    def event_count(self) -> int:
        return len(self.timeline)
