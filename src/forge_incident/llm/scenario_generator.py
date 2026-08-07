"""Brand-new scenario generation: prompt building + validate/retry loop.

This is the one place in ForgeIncident where an LLM is trusted to invent
an entire scenario (organization, actors, hosts, timeline, MITRE mapping)
rather than just pick among existing templates — see
`llm/base.py`'s `LLMBackend.generate_scenario_text` docstring for why that
split is safe: `generate`/`generate-nl`'s determinism guarantee is
untouched, because this module is only reachable from the
`generate-category` CLI command.

The core idea: an LLM's raw text output is NEVER trusted directly. It is
always run through the exact same `scenario_loader.load_scenario_from_text`
validation every hand-written YAML scenario goes through (referential
integrity, enum validity, MITRE technique ID format, chronological
ordering, etc.). If validation fails, the exact Pydantic error is fed
back to the model and it gets another attempt, up to `max_attempts`. Once
a scenario passes structural validation, `llm.consistency.check_consistency`
runs a second, heuristic pass for semantic issues schema validation can't
catch (see that module's docstring) and attaches the results as warnings
rather than blocking on them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from forge_incident.llm.base import LLMBackend, LLMBackendError
from forge_incident.llm.consistency import check_consistency
from forge_incident.models import Difficulty, Scenario
from forge_incident.scenario_categories import ScenarioCategory, get_category
from forge_incident.scenario_loader import ScenarioLoadError, load_scenario_from_text

__all__ = ["GeneratedScenario", "generate_new_scenario", "DEFAULT_MAX_ATTEMPTS"]

DEFAULT_MAX_ATTEMPTS = 3

_DIFFICULTY_GUIDANCE: dict[Difficulty, str] = {
    Difficulty.BEGINNER: (
        "8-14 timeline events. One or two hosts, one clear narrative thread, no red "
        "herrings. Clues should be findable without deep cross-referencing."
    ),
    Difficulty.INTERMEDIATE: (
        "15-24 timeline events across 2-4 hosts/actors and at least two different "
        "log_sources. Include at least one benign-looking event a student must rule "
        "out. Requires cross-referencing 2+ logs to fully answer the answer_key."
    ),
    Difficulty.ADVANCED: (
        "25-40 timeline events across several hosts/actors and at least three "
        "different log_sources. Include a deliberate defense-evasion or log-gap "
        "element (e.g. a log-clearing event, a time gap, an anti-forensics step). "
        "Requires multi-step correlation across most/all provided logs."
    ),
}

_KNOWN_EVENT_TYPES = (
    "account_login_success, account_login_failure, account_lockout, mfa_challenge, "
    "mfa_bypass, password_reset, user_created, group_membership_changed, "
    "privilege_escalation, phishing_email_delivered, phishing_email_clicked, "
    "attachment_opened, credential_harvested, email_sent, "
    "email_forwarding_rule_created, malware_download, malware_execution, "
    "process_created, process_injection, persistence_established, "
    "scheduled_task_created, registry_modified, file_created, file_modified, "
    "file_deleted, dns_query, network_connection_allowed, "
    "network_connection_blocked, c2_beacon, lateral_movement, data_staging, "
    "data_exfiltration, log_cleared, ransomware_encryption, cloud_api_call, "
    "cloud_permission_change, cloud_resource_created, cloud_resource_deleted, "
    "alert_triggered"
)

_LOG_SOURCE_GUIDE = """\
- gcp_audit: GCP Cloud Audit Log — needs `cloud` payload on the event.
- aws_cloudtrail: AWS CloudTrail — needs `cloud` payload.
- azure_activity: Azure Activity Log / Entra ID audit log — needs `cloud` payload.
- outlook_message_trace: Exchange Online Message Trace — needs `email` payload.
- email_eml: a recovered .eml message — needs `email` payload.
- palo_alto: PAN-OS firewall traffic log — needs `network` payload.
- linux: Linux syslog/auth log — typically needs `process` payload and/or \
`extra.attempt_count` for brute-force bursts; host must have os: linux (or macos, \
which also renders through this emitter — see the macOS category notes).
- windows: Windows Event Log (Sysmon-style) — typically needs `process` payload; \
host must have os: windows.
"""

_SCHEMA_REFERENCE = f"""\
Every field below is exactly what `forge_incident.models.Scenario` (a Pydantic model \
with `extra="forbid"`) accepts — using any field name not listed here, or omitting a \
required one, will fail validation. Output YAML with EXACTLY this top-level shape:

scenario_id: <slug, lowercase-hyphenated>
title: <string>
description: >
  <Full, spoiler-ful instructor-facing narrative. Multiple sentences, YAML folded \
scalar (>). This is where the WHOLE story goes, including the twist/technique names.>
student_briefing: >
  <Non-spoiler prompt shown to students. Scope the investigation (who/what/which \
logs, in-world framing) WITHOUT revealing the attack chain, technique names, or \
which host/account turns out to be compromised, the way a real engagement kickoff \
brief would. Must read as a DIFFERENT text than `description`, not a shorter copy.>
difficulty: beginner | intermediate | advanced
version: "1.0"
seed: <integer, will be provided — copy it exactly>

organization:
  name: <fictional company name>
  domain: <fictional domain, MUST end in .example (RFC 2606 reserved TLD, e.g. \
'acme.example') — never a real-world domain>
  industry: <string, optional>
  timezone: UTC
  gcp_project_id: <string, optional — also reused as AWS account ID / Azure \
subscription ID placeholder if this scenario uses aws_cloudtrail/azure_activity>

mitre_tactics: [<ATT&CK tactic names used anywhere in the timeline>]
learning_objectives: [<3-6 short strings, what a student should learn/practice>]
tags: [<lowercase short tags>]

start_time: "<ISO-8601 UTC timestamp, e.g. '2026-05-01T09:00:00Z'>"

actors:
  <short_key>:
    username: <string>
    email: <must match organization.domain>
    display_name: <string>
    department: <string, optional>
    role_title: <string, optional>
    employee_id: <string, optional>
    is_compromised: <true|false, optional, default false>
    is_privileged: <true|false, optional, default false>
  # one entry per actor referenced anywhere in the timeline, PLUS you may include an
  # "attacker" entry never referenced by any event's `actor:` field if the log
  # sources you're using genuinely couldn't attribute the action to a human
  # identity (see the gcp-leaked-service-account-key category for why — cloud
  # audit logs record the CREDENTIAL, not the human).

hosts:
  <short_key>:
    hostname: <string, UPPERCASE-STYLE is conventional>
    ip_address: <IPv4 literal, private range like 10.x/172.16-31.x/192.168.x unless \
the event is explicitly an external attacker IP>
    host_type: workstation | laptop | server | cloud_instance | domain_controller
    os: windows | linux | macos | cloud
    os_version: <string, optional>
    mac_address: <'aa:bb:cc:dd:ee:ff' format, optional>
    domain_joined: <true|false, optional, default true>

timeline:
  # ORDERED list, chronological. Each entry:
  - id: <short unique slug, e.g. 'phish-click'>
    at: "<relative offset from start_time, e.g. '+0m', '+6m', '+2h30m', '+1d3h'>"
    event_type: <one of: {_KNOWN_EVENT_TYPES}>
    log_sources: [<one or more of: gcp_audit, aws_cloudtrail, azure_activity, \
outlook_message_trace, email_eml, palo_alto, linux, windows>]
    severity: info | low | medium | high | critical
    actor: <key into actors, optional>
    host: <key into hosts, optional>
    description: >
      <Instructor-only narrative for THIS event. Never shown to students.>
    mitre:  # optional, but include on every event that represents a real ATT&CK step
      technique_id: "<e.g. 'T1566.001'>"
      technique_name: "<e.g. 'Spearphishing Attachment'>"
      tactic: "<e.g. 'Initial Access'>"
    # Exactly the typed payload(s) matching this event's log_sources — see the log
    # source guide below for which payload each log_sources value needs:
    process:
      pid: <int >= 1>
      ppid: <int >= 1, optional>
      name: <e.g. 'powershell.exe'>
      command_line: <string>
      parent_name: <string, optional>
      sha256: <64-hex-char string, optional>
      integrity_level: <string, optional, Windows only>
    email:
      message_id: "<RFC 5322 style, e.g. '<uuid@domain.example>'>"
      sender: <email>
      recipients: [<email>, ...]
      subject: <string>
      direction: inbound | outbound | internal
      spf: pass | fail | softfail | none
      dkim: pass | fail | softfail | none
      dmarc: pass | fail | softfail | none
      has_attachment: <true|false>
      attachment_name: <string, required if has_attachment>
      attachment_sha256: <64-hex-char string, optional>
      body_text: <string, optional>
      client_ip: <IPv4, optional>
    network:
      protocol: tcp | udp | icmp
      src_ip: <IPv4>
      src_port: <0-65535>
      dst_ip: <IPv4>
      dst_port: <0-65535>
      action: allow | deny | drop | reset
      app: <string, optional, e.g. 'ssl', 'dns-base'>
      rule_name: <string, optional>
      bytes_sent: <int, optional>
      bytes_received: <int, optional>
    cloud:
      method_name: <e.g. 'google.iam.admin.v1.CreateServiceAccountKey', \
'ConsoleLogin', 'Microsoft.Storage/storageAccounts/write'>
      service_name: <e.g. 'iam.googleapis.com', 'iam.amazonaws.com'>
      resource_name: <string>
      caller_ip: <IPv4>
      user_agent: <string, optional>
      status_code: <'OK' or an error code string>
      project_id: <string, optional — GCP project / AWS account / Azure subscription>
      region: <string, optional, AWS/Azure only>
    file:
      path: <string>
      filename: <string>
      sha256: <64-hex-char string, optional>
      md5: <32-hex-char string, optional>
      size_bytes: <int, optional>
    tags: [<strings, optional>]
    extra:
      # free-form dict, optional. Used e.g. for brute-force bursts:
      attempt_count: <int>  # linux/windows emitters render this many lines

answer_key:
  # 3-6 items, each grounded in specific timeline event ids
  - id: q1
    question: <string>
    answer: >
      <Full answer text>
    related_event_ids: [<ids from timeline above>]
    hint: <string, optional>
    points: <int, default 1>

LOG SOURCE GUIDE (what payload each log_sources value expects):
{_LOG_SOURCE_GUIDE}
"""

_CONSISTENCY_AND_SAFETY_RULES = """\
CRITICAL CONSISTENCY RULES (this is the single most important part of this task):
1. Every identifier that represents the SAME real-world thing must use the EXACT \
same string every time it appears, anywhere in the file. The attacker's external IP \
is one string, reused verbatim in every event it's involved in — never regenerate a \
"fresh" IP for the same actor/infrastructure. Same rule for: file hashes (the same \
file has the same sha256 everywhere), hostnames, usernames/emails, and any \
resource_name/method_name that should recur.
2. Every `actor:`/`host:` value on an event must be a key that exists in `actors`/ \
`hosts` above.
3. `timeline` must be in chronological order by `at` offset.
4. Every `mitre.technique_id` must be a REAL, correctly-formatted ATT&CK technique ID \
(Txxxx or Txxxx.xxx) that genuinely matches `technique_name`/`tactic` — do not invent \
technique IDs.
5. Do not use any field name not listed in the schema reference above — the schema \
rejects unknown fields entirely (no silent ignoring).

SAFETY / REALISM RULES:
- Every organization, person, and system in the scenario must be entirely fictional. \
Never use a real company, real person's name, or real domain.
- organization.domain and every actor email domain MUST end in `.example` (the IANA/ \
RFC 2606 reserved fictional TLD).
- Never include functional exploit code, working malware, or real credentials/API \
keys — `process.command_line` and similar fields should look realistic but must not \
be copy-pasteable working attack tooling.
- `description` (scenario-level and per-event) is instructor-only and may contain \
full spoilers, technique names, and analysis. `student_briefing` must NOT reveal the \
attack chain, technique names, or which host/account is compromised — write it the \
way a real incident intake ticket or engagement kickoff brief would read.
"""


def _system_prompt() -> str:
    return (
        "You are the scenario-generation module of ForgeIncident, an offline DFIR/ "
        "purple-team training-package generator. Unlike ForgeIncident's other planning "
        "mode (which only picks among existing templates), you are being asked to invent "
        "an entirely new, self-contained investigation scenario from scratch, following "
        "the category brief and schema given in the user message.\n\n"
        "Respond with ONLY a single YAML document — no markdown code fences, no prose "
        "before or after, starting directly with `scenario_id:`.\n\n"
        f"{_SCHEMA_REFERENCE}\n{_CONSISTENCY_AND_SAFETY_RULES}"
    )


def _user_prompt(
    category: ScenarioCategory,
    *,
    difficulty: Difficulty,
    seed: int,
    scenario_id: str,
    example_yaml: str,
    previous_error: str | None,
) -> str:
    parts = [
        f"Category: {category.name} (domain: {category.domain}, source: {category.source})",
        f"Premise: {category.summary}",
    ]
    if category.notes:
        parts.append(f"Notes: {category.notes}")
    parts.append(f"Suggested MITRE tactics to draw from: {', '.join(category.suggested_tactics) or 'any appropriate'}")
    parts.append(
        f"Suggested MITRE techniques to draw from (use real, correct IDs — these are "
        f"hints, not a strict checklist): {', '.join(category.suggested_techniques) or 'any appropriate'}"
    )
    parts.append(
        f"Suggested log_sources for this story: {', '.join(category.primary_log_sources) or 'any appropriate'} "
        "(combine with others if the story needs it, e.g. an email lure landing on an endpoint)."
    )
    parts.append(f"Difficulty: {difficulty.value} — {_DIFFICULTY_GUIDANCE[difficulty]}")
    parts.append(f"Use exactly this seed value: {seed}")
    parts.append(f"Use exactly this scenario_id: {scenario_id}")
    parts.append(
        "\nHere is a complete, valid example scenario (a DIFFERENT category) showing the "
        "exact expected style, tone, and level of detail. Do not copy its story, "
        "organization, or identifiers — write an entirely new scenario for the category "
        f"above, matching only its FORMAT:\n\n{example_yaml}"
    )
    if previous_error:
        parts.append(
            "\nYour previous attempt failed validation with this exact error — fix it and "
            f"regenerate the COMPLETE scenario from scratch (not a patch/diff):\n{previous_error}"
        )
    return "\n\n".join(parts)


_FENCE_RE = re.compile(r"```(?:ya?ml)?\s*\n(.*?)```", re.DOTALL)


def _extract_yaml(text: str) -> str:
    """Best-effort extraction of a YAML document from an LLM text response."""
    fenced = _FENCE_RE.search(text)
    if fenced:
        return fenced.group(1)
    return text.strip()


def _make_scenario_id(category: ScenarioCategory, seed: int) -> str:
    return f"gen-{category.id}-{seed}"


@dataclass
class GeneratedScenario:
    """Result of a successful `generate_new_scenario` call."""

    scenario: Scenario
    yaml_text: str
    category: ScenarioCategory
    attempts: int
    warnings: list[str] = field(default_factory=list)


def generate_new_scenario(
    backend: LLMBackend,
    *,
    category_id: str,
    difficulty: Difficulty,
    seed: int,
    example_scenario_path: str | Path,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> GeneratedScenario:
    """Generate, validate, and (on failure) retry a brand-new scenario.

    `example_scenario_path` should point at one of the bundled hand-written
    scenarios (used as a few-shot format example only — the model is
    explicitly told not to reuse its story/identifiers). Raises
    `LLMBackendError` if no valid scenario is produced within
    `max_attempts`, with the last validation error and raw output
    attached for debugging.
    """
    category = get_category(category_id)  # raises KeyError -> let caller decide how to surface
    example_yaml = Path(example_scenario_path).read_text(encoding="utf-8")
    scenario_id = _make_scenario_id(category, seed)
    system_prompt = _system_prompt()

    previous_error: str | None = None
    last_yaml_text = ""

    for attempt in range(1, max_attempts + 1):
        user_prompt = _user_prompt(
            category,
            difficulty=difficulty,
            seed=seed,
            scenario_id=scenario_id,
            example_yaml=example_yaml,
            previous_error=previous_error,
        )
        raw_text = backend.generate_scenario_text(system_prompt=system_prompt, user_prompt=user_prompt)
        yaml_text = _extract_yaml(raw_text)
        last_yaml_text = yaml_text

        try:
            scenario = load_scenario_from_text(yaml_text, scenario_id=scenario_id, seed=seed)
        except ScenarioLoadError as exc:
            previous_error = str(exc)
            continue

        warnings = check_consistency(scenario)
        return GeneratedScenario(
            scenario=scenario,
            yaml_text=yaml_text,
            category=category,
            attempts=attempt,
            warnings=warnings,
        )

    raise LLMBackendError(
        f"Could not produce a schema-valid scenario for category {category_id!r} after "
        f"{max_attempts} attempt(s). Last validation error:\n{previous_error}\n\n"
        f"Last raw model output (truncated):\n{last_yaml_text[:2000]}"
    )
