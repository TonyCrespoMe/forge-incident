# ForgeIncident — The Complete Guide

A full explanation of what this tool is, how every part of it works, every option
available, and step-by-step walkthroughs for using it to actually practice
digital forensics and incident response.

**Document version:** written August 2026, covering ForgeIncident 0.1.0.

---

## Table of contents

**Part 1 — Understanding the tool**
1. [What ForgeIncident is and the problem it solves](#1-what-forgeincident-is-and-the-problem-it-solves)
2. [The core design principle everything else follows from](#2-the-core-design-principle-everything-else-follows-from)
3. [How the pieces fit together](#3-how-the-pieces-fit-together)
4. [Installation](#4-installation)

**Part 2 — The building blocks**

5. [Anatomy of a scenario](#5-anatomy-of-a-scenario)
6. [The event timeline in detail](#6-the-event-timeline-in-detail)
7. [The eleven log generators](#7-the-eleven-log-generators)
8. [Student package vs. instructor package](#8-student-package-vs-instructor-package)

**Part 3 — Every feature**

9. [Three ways to create a scenario](#9-three-ways-to-create-a-scenario)
10. [SIEM export](#10-siem-export)
11. [The scoring system](#11-the-scoring-system)
12. [The plugin system](#12-the-plugin-system)
13. [The web UI](#13-the-web-ui)

**Part 4 — Using it to practice**

14. [Walkthrough A: your first investigation](#14-walkthrough-a-your-first-investigation)
15. [Walkthrough B: running a training session for others](#15-walkthrough-b-running-a-training-session-for-others)
16. [Walkthrough C: writing your own scenario from scratch](#16-walkthrough-c-writing-your-own-scenario-from-scratch)
17. [Walkthrough D: practicing inside a real SIEM](#17-walkthrough-d-practicing-inside-a-real-siem)
18. [Walkthrough E: adding a custom log format](#18-walkthrough-e-adding-a-custom-log-format)
19. [Building a practice curriculum](#19-building-a-practice-curriculum)

**Part 5 — Reference**

20. [Complete CLI reference](#20-complete-cli-reference)
21. [Complete field reference](#21-complete-field-reference)
22. [Configuration and environment variables](#22-configuration-and-environment-variables)
23. [Troubleshooting](#23-troubleshooting)

---

# Part 1 — Understanding the tool

## 1. What ForgeIncident is and the problem it solves

ForgeIncident is a command-line tool and web application that generates realistic,
fake security incident scenarios for training purposes. You give it a description
of an attack — or pick one from a built-in catalog of 56 categories — and it
produces two ZIP files: one for the student containing raw log files to
investigate, and one for the instructor containing the full attack narrative,
an answer key, and grading data.

### The problem it exists to solve

If you want to learn incident response, you need to practice on realistic
evidence. But getting that evidence is genuinely hard:

**Real logs from real breaches are not available.** They contain real people's
names, real IP addresses, real company data. Organizations cannot share them,
and if they could, it would be a privacy disaster.

**Hand-written fake logs are inconsistent.** This is the subtle killer. If an
instructor writes a firewall log by hand and then writes a Windows event log by
hand, the IP address in one will almost never exactly match the IP in the other.
A student who tries to pivot from the firewall log to the endpoint log finds the
trail simply doesn't connect — not because they made an analytical mistake, but
because the exercise was built wrong. This teaches students to distrust their own
correlation instincts, which is precisely the opposite of the goal.

**Generic log generators produce noise, not stories.** Tools that generate random
log traffic give you volume but no narrative. There is no attack to find, no
kill chain to reconstruct, and no correct answer to check against.

### What ForgeIncident does differently

ForgeIncident builds every log file in a package from a **single shared timeline
of events**. When an event says "the attacker connected from 185.220.101.47 at
09:14," every log format that would have recorded that connection renders it from
that same event object. The firewall log, the Okta system log, the cloud audit
log, and the SIEM export all get the exact same IP string, because they are all
reading the same source of truth.

That means cross-referencing actually works. A student can find a suspicious IP
in a firewall log, search for it in the authentication logs, and genuinely find
it — because the tool guarantees, structurally, that it is there.

### Who it is for

- **Self-learners** practicing DFIR skills without access to a corporate SOC.
- **Instructors** running a class, bootcamp, or internal training program.
- **SOC team leads** onboarding new analysts or running purple-team exercises.
- **Detection engineers** who need realistic test data with known ground truth to
  validate SIEM detection rules against.

### What it is not

It is not a malware sandbox, an attack simulator, or a tool that touches any real
system. It generates text files describing a fictional incident. Every
organization, person, hostname, and IP in a generated scenario is invented. The
tool never executes anything, never connects to any system you are investigating,
and produces no functional exploit code by design.

---

## 2. The core design principle everything else follows from

There is one rule at the center of this project, and nearly every design decision
in the codebase traces back to it:

> **All log content is generated by deterministic Python code from a single shared
> event model, so that every identifier — timestamp, IP address, username, process
> ID, file hash, message ID — stays consistent across every file in a package.**

Two important consequences follow.

### Consequence one: AI never writes log content

ForgeIncident can optionally use an LLM (Claude, OpenAI, Gemini, Grok, or a local
Ollama model), but only in two tightly scoped roles:

1. **Planning** — reading a plain-English request and choosing which existing
   scenario template best matches it.
2. **Scenario authoring** — writing a brand-new scenario *definition file* (the
   YAML), which is then validated by the same schema every hand-written scenario
   goes through.

An LLM never writes a log line. Log lines are always rendered by deterministic
Python from validated event objects. This matters because an LLM writing 300 log
lines directly would inevitably drift — the attacker's IP would subtly change
halfway through, a process ID would not match its parent, a timestamp would fall
out of order. By keeping the LLM at the level of "describe the incident" and
letting code handle "render the evidence," consistency is structural rather than
hopeful.

### Consequence two: everything is reproducible from a seed

Every scenario has a numeric `seed`. All randomness in the system — the small
timestamp jitter that stops logs looking artificially rounded, the secondary
identifiers each log format needs like a GCP `insertId` or a firewall session ID
— derives from that seed through a stable hash function, never from an unseeded
random number generator.

The practical effects:

- Running the same command twice produces **byte-identical** student ZIP files.
- You can give twenty students the same seed and know they all received exactly
  the same evidence, so grading is fair.
- You can give each student a different seed and get twenty variants of the same
  attack story with different timing details, so they cannot simply copy answers.
- A scenario you generated a year ago can be regenerated exactly today.

---

## 3. How the pieces fit together

Here is the full data flow, from input to every possible output.

```
INPUTS (three ways to define a scenario)
─────────────────────────────────────────
  A YAML scenario file        ─┐
  A plain-English prompt      ─┤─►  a validated Scenario object
  A category + difficulty     ─┘     (schema-checked, seeded)
  (or edits made in the web UI)
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
          RENDER RAW LOGS                        EXPORT TO SIEM
       (the emitters package)                    (the siem package)
                    │                                   │
   ┌────────────────┴────────────┐          ┌───────────┴──────────┐
   │ gcp_audit    aws_cloudtrail │          │ splunk (HEC JSON)    │
   │ azure_activity   okta       │          │ elastic (ECS bulk)   │
   │ crowdstrike  palo_alto      │          │ sentinel (+ KQL)     │
   │ firewall_syslog   linux     │          └──────────────────────┘
   │ windows   outlook_msg_trace │
   │ email_eml   + your plugins  │
   └────────────────┬────────────┘
                    ▼
          PACKAGE THE RESULTS
         (the packager module)
                    │
   ┌────────────────┴──────────────────┐
   │ student ZIP:                      │
   │   the log files                   │
   │   a non-spoiler briefing          │
   │   a blank submission.json         │
   ├───────────────────────────────────┤
   │ instructor ZIP:                   │
   │   the same log files              │
   │   the full attack narrative       │
   │   the answer key                  │
   │   a machine-readable manifest     │
   └────────────────┬──────────────────┘
                    │
        student investigates, fills in submission.json
                    ▼
              SCORE THE WORK
            (the scoring module)
                    │
   ┌────────────────┴──────────────────┐
   │ detection coverage (+ per tactic) │
   │ false positives / precision       │
   │ response time                     │
   └───────────────────────────────────┘
```

### The modules, in plain language

| Module | What it does |
|---|---|
| `models.py` | Defines what a scenario *is* — the shared vocabulary every other module reads. The single source of truth. |
| `scenario_loader.py` | Turns a YAML file (or YAML text) into a validated scenario object. Rejects anything malformed with a clear error. |
| `emitters/` | Eleven modules, one per log format. Each reads the shared timeline and renders it in its format. |
| `siem/` | Three modules that export the same timeline into SIEM ingest formats instead of raw logs. |
| `packager.py` | The only module that writes files to disk. Decides what goes in the student ZIP vs. the instructor ZIP. |
| `scoring.py` | Grades a student's submission against the timeline. |
| `llm/` | Optional AI backends for planning and scenario authoring. |
| `scenario_categories.py` | The catalog of 56 scenario categories used by the AI generation feature. |
| `webui/` | The browser interface. |
| `cli.py` | Wires everything together into terminal commands. |

---

## 4. Installation

### Requirements

- **Python 3.10 or newer.** Check with `python3 --version`.
- **Git** (optional — only if cloning rather than downloading a ZIP).
- No API key and no internet connection are needed for core use.

### Step by step

```bash
# 1. Get the code
git clone https://github.com/YOUR-USERNAME/forge-incident.git
cd forge-incident

# 2. Create an isolated Python environment
python3 -m venv .venv

# 3. Activate it
source .venv/bin/activate          # macOS and Linux
.venv\Scripts\Activate.ps1         # Windows PowerShell
.venv\Scripts\activate.bat         # Windows Command Prompt

# 4. Install
pip install -e ".[dev]"

# 5. Confirm it works
forge-incident version
forge-incident list
```

`forge-incident list` should print a table with the bundled scenarios, both marked
`ok`. If you see that, the installation is correct.

> **Remember:** every new terminal window needs the environment activated again
> (step 3) before `forge-incident` commands will be found.

### Optional extras

Install only what you need:

| Command | Adds |
|---|---|
| `pip install -e ".[webui]"` | The Streamlit web interface |
| `pip install -e ".[claude]"` | Anthropic Claude support |
| `pip install -e ".[openai]"` | OpenAI GPT support |
| `pip install -e ".[gemini]"` | Google Gemini support |
| `pip install -e ".[grok]"` | xAI Grok support |
| `pip install -e ".[ollama]"` | Local Ollama support (no API key) |
| `pip install -e ".[dev]"` | Test and lint tooling |
| `pip install -e ".[all]"` | Everything above |

You can combine them: `pip install -e ".[webui,dev]"`.

### Windows note

If PowerShell refuses to run the activation script, run this once and retry:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

---

# Part 2 — The building blocks

## 5. Anatomy of a scenario

A scenario is a YAML file. Here is what each section is for.

### Identity and narrative

```yaml
scenario_id: phishing-to-exfil-01     # stable slug, used in output filenames
title: "Phishing to Data Exfiltration"
difficulty: intermediate               # beginner | intermediate | advanced
version: "1.0"
seed: 20260310                         # master seed for reproducibility
```

### The two descriptions — the most important distinction in the file

```yaml
description: >
  A finance employee opens a malicious macro attachment, malware beacons out
  to a C2 server, the attacker moves laterally to a file server, stages
  sensitive data, and exfiltrates it. Detected by an EDR alert four hours in.

student_briefing: >
  Your SOC received an EDR alert on a finance workstation. You have firewall
  logs, email message trace, and Windows event logs covering March 10th.
  Determine what happened, how the attacker got in, and what data left the
  network.
```

These two fields serve completely different audiences and must never be confused:

- **`description`** is the **instructor's** version. It contains full spoilers,
  names techniques, and states the conclusion. It appears in the instructor guide
  and nowhere else.
- **`student_briefing`** is what the **student** reads. It scopes the
  investigation the way a real engagement kickoff would — what you have, what
  you're asked to determine — without revealing the answer.

This separation is enforced throughout the codebase. No log emitter, no SIEM
export, and no student-facing file ever renders `description`.

### The organization

```yaml
organization:
  name: Globex Corporation
  domain: globex.example       # note: .example is a reserved fictional TLD
  industry: Manufacturing
  timezone: UTC
  gcp_project_id: globex-prod-01   # also reused as AWS account / Azure subscription
```

Always use the `.example` top-level domain. It is reserved by RFC 2606
specifically for documentation and testing, so a generated scenario can never
accidentally reference a real company's domain.

### Teaching metadata

```yaml
mitre_tactics:
  - Initial Access
  - Execution
  - Exfiltration

learning_objectives:
  - Identify a malicious attachment from message trace headers
  - Correlate a C2 beacon across firewall and endpoint logs
  - Quantify exfiltrated data volume

tags: [phishing, malware, exfiltration]
```

### The cast — actors and hosts

```yaml
actors:
  victim:                              # short key, referenced by events
    username: jsmith
    email: jsmith@globex.example
    display_name: Jane Smith
    department: Finance
    role_title: Financial Analyst
    employee_id: GX-4471
    is_compromised: false
    is_privileged: false

hosts:
  ws-01:                               # short key, referenced by events
    hostname: FIN-WS-014
    ip_address: 10.20.30.14
    host_type: workstation             # workstation|laptop|server|cloud_instance|domain_controller
    os: windows                        # windows|linux|macos|cloud
    os_version: "Windows 11 Pro 23H2"
    mac_address: "00:1B:44:11:3A:B7"
    domain_joined: true
```

The short keys (`victim`, `ws-01`) are how timeline events refer to people and
machines. This indirection is what guarantees consistency: an event says
`actor: victim`, and every log format that renders that event looks up the same
`Identity` object and gets the same username and email.

### The anchor time

```yaml
start_time: "2026-03-10T08:00:00Z"
```

Every event's time is expressed as an offset from this. Change this one line and
the entire incident moves to a different date, with all internal spacing intact.

### The timeline and answer key

Covered in detail in the next two sections.

---

## 6. The event timeline in detail

The timeline is an ordered list of things that happened. Each entry looks like
this:

```yaml
timeline:
  - id: macro-exec
    at: "+16m"
    event_type: malware_execution
    log_sources: [windows, crowdstrike]
    severity: critical
    actor: victim
    host: ws-01
    description: >
      The macro spawns PowerShell with an encoded command that downloads
      the second-stage payload.
    mitre:
      technique_id: T1059.001
      technique_name: "PowerShell"
      tactic: Execution
    process:
      pid: 4812
      ppid: 3120
      name: powershell.exe
      command_line: "powershell.exe -enc SQBFAFgA..."
      parent_name: winword.exe
      sha256: "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900"
      integrity_level: High
```

### Field by field

**`id`** — a short unique slug. The answer key references these, and the scoring
system uses them to match student detections. Optional, but always set them; they
make everything downstream readable.

**`at`** — when this happened, relative to `start_time`. The format combines
units: `+0m`, `+16m`, `+2h30m`, `+1d3h15m`, `-10s`. You can also give a full
ISO-8601 timestamp if you need to pin something to an exact clock time.

**`event_type`** — what kind of thing happened, from a fixed list of 39 values
(see [section 21](#21-complete-field-reference)). This drives how each log format
renders it: `account_login_success` becomes Windows Event ID 4624, an Okta
`user.session.start`, and so on.

**`log_sources`** — which log formats should record this event. This is a list
because one real-world event genuinely appears in multiple places: a phishing
email appears in both the message trace and as a recovered `.eml` file. **This is
the single most important field for exercise design** — it controls what evidence
the student has and therefore how hard the investigation is.

**`severity`** — `info`, `low`, `medium`, `high`, or `critical`. Used by log
formats that carry a severity level, and by the scoring system to decide what
counts as something a student should have caught.

**`actor` / `host`** — short keys pointing into the `actors` and `hosts`
registries. Optional; some events legitimately have no identifiable user (cloud
audit logs record the credential, not the human behind it).

**`description`** — instructor-only narrative for this specific event. Appears in
the instructor guide. **Never rendered into any log file.**

**`mitre`** — the ATT&CK technique this represents. Optional but strongly
recommended: the scoring system uses it to build per-tactic coverage breakdowns,
and the SIEM exports map it to native threat fields.

### The typed payloads

Beyond the common fields, an event carries whichever detail block matches what
kind of event it is. You include only the ones relevant to that event's
`log_sources`.

| Payload | Used by | Carries |
|---|---|---|
| `process` | windows, linux, crowdstrike | pid, ppid, name, command_line, parent_name, sha256, integrity_level |
| `email` | outlook_message_trace, email_eml | message_id, sender, recipients, subject, direction, spf/dkim/dmarc, attachment details, body_text, client_ip |
| `network` | palo_alto, firewall_syslog | protocol, src_ip, src_port, dst_ip, dst_port, action, app, rule_name, bytes_sent, bytes_received |
| `cloud` | gcp_audit, aws_cloudtrail, azure_activity | method_name, service_name, resource_name, caller_ip, user_agent, status_code, project_id, region |
| `file` | windows, linux, crowdstrike | path, filename, sha256, md5, size_bytes |

**`extra`** is a free-form dictionary for anything not worth formally modeling.
One special use: `extra.attempt_count` makes the Linux and Windows emitters
render that many consecutive attempts, which is how a brute-force burst becomes
47 realistic log lines instead of one suspiciously summarized line.

### The answer key

```yaml
answer_key:
  - id: q1
    question: "How did the attacker gain initial access?"
    answer: >
      A phishing email with a macro-enabled spreadsheet attachment, delivered
      at 08:00 and opened by Jane Smith at 08:14.
    related_event_ids: [delivered, opened]
    hint: "Start with the message trace and work forward."
    points: 2
```

`related_event_ids` ties each question back to specific timeline events, which is
what makes the instructor guide traceable — for any answer, you can point at the
exact log lines that support it.

### Validation — what the loader enforces

When a scenario is loaded, it is checked for:

- Every `actor` and `host` reference points to something that actually exists.
- No duplicate event IDs.
- Every `answer_key` reference points to a real event.
- The timeline is in chronological order.
- Every MITRE technique ID matches the real format (`T1566` or `T1566.001`).
- Every enum value is a real allowed value.
- **No unknown fields** — a typo like `sevrity:` is rejected rather than silently
  ignored.

If any check fails, the file is rejected with a message naming the file, the
event, and the specific field. Nothing partially-valid ever generates a package.

### Timestamp jitter

By default, each event's timestamp is nudged by up to plus or minus three seconds
using the seed. This exists because real logs never land on suspiciously round
numbers — an event at exactly `08:16:00` looks synthetic. Jitter never reorders
events; if a jittered timestamp would land before the previous event, it is
clamped to one second after it. Set `timestamp_jitter_seconds: 0` at the top level
to disable it.

---

## 7. The eleven log generators

Each generator ("emitter") reads the shared timeline, filters it to events whose
`log_sources` include that format, and renders those events in its own format.

| `log_sources` value | Real-world format | Output file | Needs payload |
|---|---|---|---|
| `windows` | Windows Event Log XML (Security + Sysmon) | `logs/windows/<host>-events.xml` | `process` (usually) |
| `linux` | Linux syslog / auth.log | `logs/linux/<host>-syslog.log` | `process` or `extra` |
| `palo_alto` | PAN-OS traffic log CSV | `logs/palo_alto/traffic.csv` | `network` |
| `firewall_syslog` | FortiGate-style key=value syslog | `logs/firewall_syslog/traffic.log` | `network` |
| `okta` | Okta System Log JSON | `logs/okta/system_log.jsonl` | none required |
| `crowdstrike` | CrowdStrike Falcon detections JSON | `logs/crowdstrike/detections.jsonl` | `process` or `file` |
| `outlook_message_trace` | Exchange Online message trace CSV | `logs/outlook_message_trace/message_trace.csv` | `email` |
| `email_eml` | Recovered RFC 5322 email files | `logs/email_eml/<subject-slug>.eml` | `email` |
| `gcp_audit` | GCP Cloud Audit Log JSON | `logs/gcp_audit/<project>-cloudaudit.jsonl` | `cloud` |
| `aws_cloudtrail` | AWS CloudTrail JSON | `logs/aws_cloudtrail/<account>-cloudtrail.jsonl` | `cloud` |
| `azure_activity` | Azure Activity / Entra ID audit JSON | `logs/azure_activity/<sub>-activity.jsonl` | `cloud` |

### Notes on specific generators

**Windows** maps event types to real native Event IDs — 4624 for a successful
logon, 4625 for a failure, 4698 for a scheduled task, Sysmon 1 for process
creation, Sysmon 3 for a network connection, Sysmon 11 for file creation. One XML
file is produced per host.

**Two firewall formats.** `palo_alto` produces a Panorama-style CSV;
`firewall_syslog` produces FortiGate-style `key=value` lines. Routing the same
event to both is a deliberately useful exercise — students must reconcile one
session as represented by two vendors' schemas, which is exactly the
"normalize before you correlate" lesson SIEM work demands.

**Okta** resolves the client IP from whatever the event already carries, in
order: `network.src_ip`, then `cloud.caller_ip`, then the host's IP. So an
attacker IP visible in the firewall log appears byte-identical in Okta with no
extra effort from the scenario author.

**CrowdStrike** is the one place ATT&CK labels appear in student-facing evidence.
This is deliberate: a real Falcon console genuinely displays a tactic and
technique on a detection, so hiding it would make the log unrealistic. Be aware
this hands students the ATT&CK mapping for those events — which is realistic and
often the point (triaging EDR alerts), but if you want students to derive the
mapping themselves, do not route those events to `crowdstrike`.

**Empty formats produce nothing.** If no event in your scenario uses `okta`, no
Okta file appears. Packages never contain hollow header-only files.

### The consistency guarantee in practice

Because all eleven read the same event objects:

- A process ID in a CrowdStrike detection is the same number as in the Sysmon
  record for that event.
- An IP in the firewall log is the same string as in Okta and the cloud audit log.
- A file hash in a Windows event is the same hash in the Linux log.
- A message ID in the message trace matches the recovered `.eml` file.

Nothing about that is per-emitter effort. It falls out of the architecture.

---

## 8. Student package vs. instructor package

Every generation produces two ZIP files.

| Contents | Student ZIP | Instructor ZIP |
|---|---|---|
| Raw log files | Yes | Yes (identical bytes) |
| `README.md` — non-spoiler briefing | Yes | Yes |
| `submission.json` — blank answer form | Yes | Yes |
| `instructor/INSTRUCTOR_GUIDE.md` — full narrative, annotated timeline, MITRE mapping | No | Yes |
| `instructor/ANSWER_KEY.md` — questions with answers and hints | No | Yes |
| `instructor/manifest.json` — machine-readable data for grading tools | No | Yes |
| `instructor/scenario_source.yaml` — the original definition | No | Yes |

Filenames encode the scenario and seed, so different seeds never overwrite each
other:

```
phishing-to-exfil-01-seed20260310-student.zip
phishing-to-exfil-01-seed20260310-instructor.zip
```

### What the instructor guide contains

- The full narrative with spoilers.
- The learning objectives.
- Tables of every actor and host, including which are compromised.
- **An annotated timeline** — every event in order with its timestamp, event ID,
  type, MITRE technique, actor, host, and instructor description.
- If the scenario was AI-generated, a prominent "review before classroom use"
  notice plus any automated consistency warnings.

### The reproducibility guarantee

Student ZIPs are byte-identical across runs with the same seed. Every file inside
uses a fixed archive timestamp specifically so two runs produce the same bytes.
The one intentional exception is the instructor manifest's `generated_at` field,
which records real wall-clock time for provenance.

---

# Part 3 — Every feature

## 9. Three ways to create a scenario

### Method 1: from a YAML file (fully offline, fully deterministic)

```bash
forge-incident generate scenarios/phishing_to_exfil.yaml
forge-incident generate scenarios/phishing_to_exfil.yaml --seed 42
forge-incident generate scenarios/phishing_to_exfil.yaml -o ~/Desktop/exercise
```

This is the workhorse. No AI, no network, completely predictable. Use it for
grading a cohort, for CI-testing a scenario you are writing, and any time you
want certainty.

### Method 2: from a plain-English prompt

```bash
forge-incident generate-nl "a phishing email leading to data exfiltration"
forge-incident generate-nl "cloud credential leak" --difficulty beginner
forge-incident generate-nl "ransomware at a law firm" --llm claude
```

**Be clear on what this does:** it does not invent a new attack. It reads your
prompt, picks whichever existing scenario file best matches, and optionally
adjusts the difficulty label and title. It prints its reasoning so the choice is
never a black box.

The default backend (`none`) does this with simple keyword matching — no API key,
no network, no extra dependency. Choosing an actual LLM backend just makes the
matching smarter.

### Method 3: AI-generated brand-new scenarios

```bash
forge-incident categories                                  # browse the catalog
forge-incident categories --domain windows_enterprise      # one domain
forge-incident generate-category --category windows-ad-kerberoasting \
    --difficulty advanced --llm claude
```

This genuinely invents a new scenario — new organization, new cast, new timeline,
new answer key — for a category you choose from a catalog of **56 categories
across 12 domains**:

| Domain | Source | Examples |
|---|---|---|
| `web_app` | OWASP Top 10:2025 | broken access control, injection, security misconfiguration |
| `api` | OWASP API Security Top 10 | BOLA, broken authentication, mass assignment |
| `cicd_supply_chain` | OWASP Top 10 CI/CD | poisoned pipeline execution, dependency chain abuse |
| `ai_llm` | OWASP Top 10 for LLM Apps | prompt injection, excessive agency, RAG data leakage |
| `mobile` | OWASP Mobile Top 10 | insecure data storage, AiTM on public wifi |
| `aws` | AWS IR guidance | leaked IAM key, public S3, SSRF to instance metadata |
| `azure` | Microsoft IR playbooks | AiTM token theft, malicious OAuth app, AD FS certificate theft |
| `gcp` | Google threat model | leaked service account key, public bucket, IAM lateral movement |
| `windows_enterprise` | CISA/NSA AD guidance | Kerberoasting, LSASS dumping, DCSync, ransomware via RDP |
| `linux_unix` | SANS FOR508 | SSH brute force, web shell, sudo privilege escalation |
| `macos` | SANS FOR518 | fake update malware, keychain theft, TCC bypass |
| `cross_cutting` | DFIR staples | phishing chains, business email compromise, insider threat |

**How the safety net works.** The AI's raw output is never trusted. It goes
through the exact same schema validation every hand-written scenario faces. If it
fails, the specific validation error is fed back to the model and it tries again,
up to three attempts by default. Once it passes, a second heuristic check looks
for problems schema validation cannot catch — an actor defined but never used, an
IP that looks regenerated instead of reused, a filename appearing with two
different hashes.

The accepted YAML is saved to `scenarios/generated/` so it is reviewable and
reusable exactly like a hand-written one, and the instructor package is flagged
**"LLM-generated — review before classroom use."** The student package is
untouched; students cannot tell the difference.

**This costs real money.** Roughly a fraction of a cent to a few cents per
scenario on OpenAI/Gemini/Grok, low-teens-of-cents on Claude. See
`COST_ESTIMATES.md`. This is the only feature that requires an API key —
`--llm none` is not sufficient here, because genuinely inventing a scenario needs
real model creativity.

### Options for `generate-category`

| Option | Purpose |
|---|---|
| `--category` | Required. The category ID from `forge-incident categories`. |
| `--difficulty` | `beginner` (8-14 events), `intermediate` (15-24), `advanced` (25-40). |
| `--llm` | Which provider. Required — `none` will not work. |
| `--seed` | Reproducibility seed. |
| `--max-attempts` | Validation retries before giving up. Default 3. |
| `--save-dir` | Where accepted YAML lands. Default `scenarios/generated`. |
| `--output` | Where the ZIPs go. |

---

## 10. SIEM export

Instead of handing out flat files, load the scenario into a real SIEM and have
students work it in the tool they will actually use at work.

```bash
forge-incident export scenarios/phishing_to_exfil.yaml                    # all formats
forge-incident export scenarios/phishing_to_exfil.yaml -f splunk          # one
forge-incident export scenarios/phishing_to_exfil.yaml -f elastic -f sentinel
```

### The three formats

**Splunk** — `output/siem/splunk/<scenario>-hec.json`. Newline-delimited HTTP
Event Collector envelopes. Fields are deliberately flat (`process_command_line`,
not a nested object) because Splunk's default JSON extraction handles flat keys
cleanly and CIM-style names are what most Splunk content expects. Each event's
`sourcetype` derives from its log source (`forge:windows`, `forge:okta`), so
`sourcetype=forge:*` searches work.

```bash
curl -k https://localhost:8088/services/collector/event \
     -H "Authorization: Splunk YOUR-HEC-TOKEN" \
     --data-binary @output/siem/splunk/phishing-to-exfil-01-hec.json
```

**Elastic** — `output/siem/elastic/<scenario>-bulk.ndjson`. Mapped onto Elastic
Common Schema 8.11 (`@timestamp`, `event.category`, `source.ip`, `user.name`,
`process.pid`, `threat.technique.id`), not dumped as an arbitrary blob — so
Kibana's out-of-the-box visualizations and ECS-based detection rules work
immediately.

```bash
curl -H 'Content-Type: application/x-ndjson' \
     -XPOST 'http://localhost:9200/_bulk' \
     --data-binary @output/siem/elastic/phishing-to-exfil-01-bulk.ndjson
```

**Microsoft Sentinel** — two files. A Log Analytics JSON file targeting a
`ForgeIncident_CL` custom table, plus **a starter `.kql` file** containing five
working queries so you can paste something useful into the Logs blade instead of
reverse-engineering column names:

1. Full timeline, oldest first.
2. High-severity events only.
3. External IPs with data volumes.
4. Process ancestry.
5. ATT&CK coverage summary (instructor view).

### One deliberate difference from student log packages

SIEM exports **do** include ATT&CK fields. This is intentional and documented: a
SIEM export with no threat mapping cannot be used to validate detection rules,
which is a primary reason to load one. Since SIEM exports are an instructor-side
artifact — you load them into your own tenant — this is acceptable.
`Event.description` is still never exported anywhere.

---

## 11. The scoring system

Every student package contains a blank `submission.json`. Students fill it in as
they investigate; you grade it.

### What a student fills in

```json
{
  "analyst": "Jane Doe",
  "scenario_id": "phishing-to-exfil-01",
  "detections": [
    {
      "event_id": "macro-exec",
      "detected_at": "2026-03-10T08:20:00Z",
      "notes": "PowerShell spawned by Word — clearly not normal"
    },
    { "event_id": "c2-beacon", "detected_at": "2026-03-10T08:45:00Z" }
  ],
  "answers": {
    "q1": "A phishing email with a macro attachment.",
    "q2": "..."
  }
}
```

`detected_at` is optional — include it only if your course is measuring response
time. A detection can also be written as a bare string if you only care about
coverage: `"detections": ["macro-exec", "c2-beacon"]`.

### Grading

```bash
forge-incident score scenarios/phishing_to_exfil.yaml submission.json \
    --seed 20260310 --output ./reports
```

```
      Score: Jane Doe — Phishing to Data Exfiltration
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                  ┃                     Result ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Detection coverage      │                70%  (7/10) │
│ Precision               │ 88%  (1 false positive(s)) │
│ Time to first detection │                     12 min │
│ Mean detection latency  │                     41 min │
└─────────────────────────┴────────────────────────────┘
```

### The three metrics, and why each exists

**Detection coverage** — of the events a competent analyst should have flagged,
how many did they find? Reported overall *and broken down per ATT&CK tactic*, so
"they caught the malware but missed the entire exfiltration phase" is visible
rather than averaged into a single number that hides it.

**Precision / false positives** — how many things did they flag that were not
actually malicious? Tracked separately from misses for a specific reason: an
analyst who flags every single event would otherwise score 100% coverage. Two
kinds are distinguished — flagging a benign event, and referencing an event ID
that does not exist at all.

**Response time** — per-detection latency (how long after each event occurred did
they catch it) plus time-to-first-detection measured from the first malicious
event. This is the metric separating "found it eventually" from "would have
caught it before the data left."

### What counts as something they should have caught

By default: any event carrying a MITRE technique **or** with severity `medium` or
above. Everything else is benign, and flagging one is a false positive. Scenario
authors do not annotate anything extra — this falls out of fields scenarios
already set.

### Properties worth knowing

- **Deterministic.** Same scenario plus same submission always produces identical
  numbers. Two instructors grading the same work agree by construction.
- **Fully offline.** No AI involved in grading at all.
- **Seed-sensitive.** Pass the same `--seed` the student's package used, or
  timestamps will not line up and response-time scoring becomes meaningless.
- **Written answers are never auto-graded.** They are surfaced in the report for
  you to mark by hand, because judging prose is a human job.

With `--output`, you get a Markdown report (including a table of exactly which
events were missed, with their timestamps and MITRE mappings) and a JSON file for
gradebook tooling.

---

## 12. The plugin system

If you need a log format ForgeIncident does not ship, you can add one without
forking the project.

### The easy way — drop a file in `plugins/`

```python
# plugins/zeek.py
from forge_incident.emitters import EmittedArtifact, PluginEmitter


class ZeekEmitter(PluginEmitter):
    log_source_name = "zeek"

    def emit(self, scenario):
        events = [e for e in self.relevant_events(scenario) if e.network is not None]
        if not events:
            return []
        lines = [
            f"{e.timestamp.timestamp():.6f}\t{e.network.src_ip}\t{e.network.dst_ip}"
            for e in events
        ]
        return [
            EmittedArtifact(
                relative_path="logs/zeek/conn.log",
                content="\n".join(lines) + "\n",
                description=f"Zeek conn.log ({len(events)} connections).",
            )
        ]
```

Route events to it in your scenario YAML:

```yaml
  - id: c2-beacon
    event_type: c2_beacon
    log_sources: [palo_alto]        # built-in sources
    extra:
      log_sources_extra: [zeek]     # plugin sources
```

Then verify:

```bash
forge-incident plugins
```

### The packaged way — an installable plugin

```toml
[project.entry-points."forge_incident.emitters"]
zeek = "my_forge_plugin.zeek:ZeekEmitter"
```

Once `pip install`ed into the same environment, it is discovered automatically.

### Why plugin output is automatically consistent

Your plugin receives the same validated `Scenario` object the built-ins do. It
reads the same event objects, the same IPs, the same hashes. Consistency with
every other log is structural — you cannot accidentally break it, and you do not
have to do anything to earn it.

### Failure isolation

A plugin that fails to import, defines no emitter class, or raises an exception
during rendering is caught, isolated, and reported by `forge-incident plugins`
with the specific reason. It never destroys an otherwise-valid generation run.
Built-in emitters are deliberately *not* wrapped this way — a built-in failing is
a bug in the project and should surface loudly.

---

## 13. The web UI

```bash
pip install -e ".[webui]"
forge-incident web
```

Opens at `http://localhost:8501`. Options: `--port` to change the port,
`--scenarios-dir` to point at a different scenario folder.

### The seven tabs

**Timeline** — a spreadsheet-style grid of every event. Edit cells directly, add
a row for a new event, delete a row to remove one. `log_sources` is
comma-separated. Typed payloads are preserved through grid edits and edited in the
YAML tab. Click **Apply timeline changes** to commit.

**Details** — title, difficulty, seed, organization, and the student
briefing / instructor description side by side so you can see exactly what each
audience gets.

**YAML** — the complete source. Edits are validated before being applied; invalid
YAML shows the specific error rather than being accepted. Download or save to
disk from here.

**Generate** — build both ZIPs, download them, and preview any file inside the
student package in-browser.

**SIEM export** — pick formats, preview the output, download a bundle.

**Score** — upload a student's `submission.json` and get the metrics, a per-tactic
table, and downloadable Markdown and JSON reports.

**Plugins** — which log generators are loaded and what failed to load.

### One thoughtful behavior worth knowing

If you delete a timeline row that an answer-key question references, the UI
detects it and offers to clean up the broken pointers — keeping the questions
themselves — instead of letting you finish editing and then failing validation.

### The guarantee

Everything in the UI calls the same functions the CLI does. A package built in the
browser is byte-identical to `forge-incident generate` at the same seed. Nothing
is web-only or CLI-only.

---

# Part 4 — Using it to practice

## 14. Walkthrough A: your first investigation

This is how to use ForgeIncident to practice on yourself. The trick is
**generating the package, then not looking at the instructor ZIP** until you are
done.

### Step 1 — generate an exercise

```bash
cd ~/Documents/forge-incident
source .venv/bin/activate
forge-incident generate scenarios/phishing_to_exfil.yaml
```

You now have two ZIPs in `output/`.

### Step 2 — set up your workspace honestly

```bash
mkdir -p ~/practice/case-001
cd ~/practice/case-001
unzip ~/Documents/forge-incident/output/phishing-to-exfil-01-seed20260310-student.zip
```

**Do not unzip the instructor package.** Move it somewhere out of sight if you
are tempted. The entire value of the exercise depends on this.

### Step 3 — read the briefing and set a timer

```bash
cat README.md
```

Note the start time. If you want to practice under realistic pressure, give
yourself a fixed window — 45 minutes for an intermediate scenario is reasonable.

### Step 4 — inventory your evidence

```bash
find . -type f | sort
```

Before reading any content, know what sources you have. In a real engagement this
is the first question: what visibility do I actually have?

### Step 5 — build a timeline, working the evidence

Open `submission.json` in an editor and keep it beside you. Every time you find
something suspicious, add an entry immediately — including the real clock time
you found it, if you are tracking response time.

Useful starting moves depending on what you were given:

```bash
# What does the email evidence show?
column -s, -t logs/outlook_message_trace/message_trace.csv | less -S

# Any outbound connections to unusual destinations?
column -s, -t logs/palo_alto/traffic.csv | less -S

# What processes ran, and what spawned them?
grep -A3 "CommandLine" logs/windows/*.xml | less

# Pretty-print JSON log lines one at a time
head -1 logs/okta/system_log.jsonl | python -m json.tool
```

The core loop: **form a hypothesis, then look for corroborating or contradicting
evidence in a different log.** If you think an IP is the attacker's, search for it
everywhere:

```bash
grep -ri "185.220.101.47" logs/ | cut -c1-160
```

That single command is the whole point of the tool. Because every log was built
from one timeline, the IP genuinely appears in every source that would have
recorded it.

### Step 6 — answer the questions

`submission.json` contains an `answers` object with a key per question. You can
see the questions themselves in the instructor package — but since you are not
opening that, answer in the order you reconstructed things and let the scoring
report tell you which question was which.

For self-practice, an easier flow: peek at *only* `instructor/ANSWER_KEY.md`'s
question headings without reading the answers:

```bash
unzip -p output/...-instructor.zip instructor/ANSWER_KEY.md | grep '^## '
```

### Step 7 — score yourself

```bash
cd ~/Documents/forge-incident
forge-incident score scenarios/phishing_to_exfil.yaml \
    ~/practice/case-001/submission.json --seed 20260310 -o ./reports
```

### Step 8 — the part that actually teaches you

Now open the instructor guide and read it against your report.

```bash
unzip -o output/...-instructor.zip -d ~/practice/case-001-answers
less ~/practice/case-001-answers/instructor/INSTRUCTOR_GUIDE.md
```

For each missed event in your score report, ask the diagnostic question: **was
the evidence there and I did not look, or did I look and misread it?** Those are
different failures with different fixes. The first is a process problem — you
need a more systematic sweep. The second is a knowledge problem — you need to
learn what that log line means.

### Step 9 — run it again with a different seed

```bash
forge-incident generate scenarios/phishing_to_exfil.yaml --seed 777
```

Same attack story, different timing details. Good for drilling the *process*
until your sweep is systematic.

---

## 15. Walkthrough B: running a training session for others

### Step 1 — pick or generate scenarios

```bash
forge-incident list                      # what you already have
forge-incident categories                # the full catalog for AI generation
```

### Step 2 — decide your seed strategy

**One seed for everyone** — everyone gets identical evidence, grading is directly
comparable, discussion is easy because everyone saw the same thing.

```bash
forge-incident generate scenarios/phishing_to_exfil.yaml --seed 1001
```

**One seed per student** — same story, different details, so answers cannot be
shared.

```bash
for seed in 1001 1002 1003 1004 1005; do
    forge-incident generate scenarios/phishing_to_exfil.yaml --seed $seed \
        -o ./class-packages
done
```

**Record which student got which seed.** You need it at grading time.

### Step 3 — distribute

Send each student only their `*-student.zip`. Keep every `*-instructor.zip`.

### Step 4 — brief the class

Tell them to fill in `submission.json` as they work and hand it back. If you are
measuring response time, explicitly tell them to record `detected_at` as they go —
not reconstructed afterward, which defeats the purpose.

### Step 5 — grade

```bash
forge-incident score scenarios/phishing_to_exfil.yaml submissions/jane.json \
    --seed 1001 -o ./reports
forge-incident score scenarios/phishing_to_exfil.yaml submissions/bob.json \
    --seed 1002 -o ./reports
```

Match the seed to the student. A mismatched seed makes response-time scoring
meaningless.

### Step 6 — run the debrief off the per-tactic table

The per-tactic coverage breakdown is the most useful teaching artifact. If the
whole class scored well on Initial Access and badly on Exfiltration, that is your
next lesson, and it is visible in a way a single percentage would hide.

The Markdown report's "Missed detection opportunities" table gives you exactly
what to walk through, with timestamps and MITRE mappings.

---

## 16. Walkthrough C: writing your own scenario from scratch

Writing scenarios is itself excellent practice — building an attack chain forces
you to think about what each stage would actually leave behind.

### Step 1 — start from a working example

```bash
cp scenarios/phishing_to_exfil.yaml scenarios/my_scenario.yaml
```

`phishing_to_exfil.yaml` is heavily commented. `gcp_key_compromise.yaml` is a good
second reference — it uses different log sources and makes a specific
pedagogical point about cloud logs identifying credentials rather than humans.

### Step 2 — outline the attack before touching YAML

On paper: how did they get in, what did they do next, what did they take, how were
they caught? Then for each step ask **what would this leave behind, and in which
log?** That mapping becomes your `log_sources`.

### Step 3 — fill in identity and cast

Set `scenario_id`, `title`, `seed`, the organization (keep the `.example`
domain), then your actors and hosts.

### Step 4 — write the timeline

Work in `at:` offsets. Give every event an `id`, a `description` (spoilers fine —
instructor only), a `mitre` mapping where it applies, and the payload block
matching its log sources.

### Step 5 — validate constantly

```bash
forge-incident list --scenarios-dir scenarios
```

This validates every file and names the exact bad field. Run it after every few
events rather than writing 30 events and debugging a wall of errors.

### Step 6 — write the answer key

Every question should reference the specific events that answer it via
`related_event_ids`. This is what makes the exercise gradeable and the instructor
guide traceable.

### Step 7 — generate and inspect your own work

```bash
forge-incident generate scenarios/my_scenario.yaml
```

Unzip the student package and read it as a student would. The critical question:
**is it actually solvable from the evidence provided?** It is very easy to write a
scenario where the key clue exists only in your head. If a question cannot be
answered from the logs, either add an event that provides the evidence or rewrite
the question.

### Step 8 — check the difficulty is honest

Rough guide: beginner is 8-14 events with one clear thread and no red herrings;
intermediate is 15-24 events across several hosts needing cross-log correlation;
advanced is 25-40 events with defense evasion, log gaps, or misleading detail.

### A tip on realism

Add benign events. Both bundled scenarios are entirely malicious, which means
false-positive scoring cannot really be exercised against them. A few normal
logins and legitimate file saves — `severity: info`, no `mitre` block — make the
exercise far more realistic and make the precision metric meaningful.

---

## 17. Walkthrough D: practicing inside a real SIEM

Working flat files teaches log reading. Working a SIEM teaches the query language
and the workflow you will actually use in a SOC.

### Step 1 — export

```bash
forge-incident export scenarios/phishing_to_exfil.yaml -f splunk
```

### Step 2 — load it

For Splunk, with HEC enabled and a token created:

```bash
curl -k https://localhost:8088/services/collector/event \
     -H "Authorization: Splunk YOUR-TOKEN" \
     --data-binary @output/siem/splunk/phishing-to-exfil-01-hec.json
```

For Elastic:

```bash
curl -H 'Content-Type: application/x-ndjson' \
     -XPOST 'http://localhost:9200/_bulk' \
     --data-binary @output/siem/elastic/phishing-to-exfil-01-bulk.ndjson
```

For Sentinel, ingest the JSON via the Logs Ingestion API against your DCR, then
open `*-starter-queries.kql` and paste the first query.

### Step 3 — practice querying rather than grepping

```
index=forge_incident | sort _time | table _time action user src_ip dest_ip
index=forge_incident severity IN ("high","critical")
index=forge_incident | stats sum(bytes_out) by src_ip | sort -sum(bytes_out)
```

### Step 4 — write detection rules against known ground truth

This is the detection-engineering exercise, and it is where the ATT&CK fields in
the export earn their place. You know exactly what the attack was, so you can:

1. Write a rule you think would catch a stage of it.
2. Run it against the data.
3. Check whether it fires on the right events — and how many benign events it
   also hits.

That last number is your false-positive rate, measured against ground truth you
actually possess. That is very hard to practice any other way.

---

## 18. Walkthrough E: adding a custom log format

Say your environment uses a format ForgeIncident does not ship, and you want
exercises that include it.

### Step 1 — create the plugin

```bash
mkdir -p plugins
```

Write `plugins/myformat.py` following the pattern in
[section 12](#12-the-plugin-system). Decide which payload your format needs
(`network` for a network log, `process` for endpoint telemetry) and filter to
events that have it.

### Step 2 — confirm it is discovered

```bash
forge-incident plugins
```

Your class should appear in a "Plugin log generators" table. If it does not, the
error message tells you exactly why — a syntax error, a missing base class, or no
emitter defined in the file.

### Step 3 — route events to it

```yaml
    extra:
      log_sources_extra: [myformat]
```

### Step 4 — generate and check correlation

```bash
forge-incident generate scenarios/my_scenario.yaml
unzip -o output/...-student.zip -d /tmp/check
grep -r "185.220.101.47" /tmp/check/logs/
```

Your new format should appear alongside the built-ins with the same IP. If it
does, your plugin is correctly reading from the shared timeline.

---

## 19. Building a practice curriculum

A suggested progression for self-study:

**Phase 1 — single-source reading.** Write or generate beginner scenarios using
one log source at a time. Learn what a Windows 4624 looks like, what a PAN-OS
traffic row contains, what fields an Okta record has. Goal: fluency in reading
each format.

**Phase 2 — two-source correlation.** Intermediate scenarios routing events to
exactly two log sources. Goal: the pivot habit — find something in one log, prove
or disprove it in another.

**Phase 3 — full-timeline reconstruction.** Intermediate to advanced with four or
more sources. Goal: build a complete kill chain and quantify impact.

**Phase 4 — response time under pressure.** Same scenarios, but set a timer and
record `detected_at` honestly. Goal: speed without losing coverage. Watch whether
your precision drops as you go faster — that trade-off is the real lesson.

**Phase 5 — detection engineering.** SIEM export, write rules, measure them
against ground truth.

**Phase 6 — authoring.** Write scenarios for others. Nothing exposes gaps in your
understanding of an attack chain faster than having to specify what evidence each
stage leaves behind.

Track your scores over time. The JSON reports are designed to be machine-readable
precisely so you can chart coverage and response time across many exercises.

---

# Part 5 — Reference

## 20. Complete CLI reference

### `forge-incident generate SCENARIO.yaml`

Generate packages deterministically from a YAML file.

| Option | Default | Purpose |
|---|---|---|
| `--seed N` | scenario's own | Override the seed |
| `--output`, `-o DIR` | `./output` | Where ZIPs go |

### `forge-incident generate-nl "PROMPT"`

Generate from a plain-English prompt by matching an existing scenario.

| Option | Default | Purpose |
|---|---|---|
| `--seed N` | `$FORGE_DEFAULT_SEED` or 1337 | Seed |
| `--llm NAME` | `$FORGE_LLM_BACKEND` or `none` | `none`, `claude`, `openai`, `gemini`, `grok`, `ollama` |
| `--difficulty LEVEL` | inferred | Force `beginner`/`intermediate`/`advanced` |
| `--scenarios-dir DIR` | `scenarios` | Where to look for templates |
| `--output`, `-o DIR` | `./output` | Where ZIPs go |

### `forge-incident generate-category --category ID`

AI-invent a brand-new scenario. Requires a real LLM backend.

| Option | Default | Purpose |
|---|---|---|
| `--category ID` | required | From `forge-incident categories` |
| `--difficulty LEVEL` | `intermediate` | Target difficulty |
| `--llm NAME` | `$FORGE_LLM_BACKEND` | Provider; `none` not allowed |
| `--seed N` | 1337 | Seed |
| `--max-attempts N` | 3 | Validation retries |
| `--scenarios-dir DIR` | `scenarios` | Few-shot examples source |
| `--save-dir DIR` | `scenarios/generated` | Where accepted YAML lands |
| `--output`, `-o DIR` | `./output` | Where ZIPs go |

### `forge-incident categories`

Browse the 56-category catalog. `--domain ID` filters to one domain.

### `forge-incident list`

Discover and validate every scenario in a directory. Doubles as a linter —
invalid files are listed with their specific error. `--scenarios-dir DIR` to
change location.

### `forge-incident export SCENARIO.yaml`

Export to SIEM ingest formats.

| Option | Default | Purpose |
|---|---|---|
| `--format`, `-f NAME` | all three | `splunk`, `elastic`, `sentinel`. Repeatable. |
| `--seed N` | scenario's own | Seed |
| `--output`, `-o DIR` | `./output` | Where files go |

### `forge-incident score SCENARIO.yaml SUBMISSION.json`

Grade a submission.

| Option | Default | Purpose |
|---|---|---|
| `--seed N` | scenario's own | **Must match the student's package** |
| `--output`, `-o DIR` | none | Write Markdown + JSON reports |

### `forge-incident plugins`

List built-in and plugin log generators and report load failures.
`--plugins-dir DIR` to change location.

### `forge-incident web`

Launch the browser UI. `--port N` (default 8501), `--scenarios-dir DIR`.

### `forge-incident version`

Print the installed version.

---

## 21. Complete field reference

### Difficulty
`beginner` · `intermediate` · `advanced`

### Severity
`info` · `low` · `medium` · `high` · `critical`

### Host type
`workstation` · `laptop` · `server` · `cloud_instance` · `domain_controller`

### Operating system
`windows` · `linux` · `macos` · `cloud`

### Log sources
`gcp_audit` · `aws_cloudtrail` · `azure_activity` · `okta` · `crowdstrike` ·
`outlook_message_trace` · `palo_alto` · `firewall_syslog` · `linux` · `windows` ·
`email_eml`

### Network
Protocol: `tcp` · `udp` · `icmp`
Action: `allow` · `deny` · `drop` · `reset`

### Email
Direction: `inbound` · `outbound` · `internal`
SPF/DKIM/DMARC result: `pass` · `fail` · `softfail` · `none`

### All 39 event types

**Identity and authentication**
`account_login_success` · `account_login_failure` · `account_lockout` ·
`mfa_challenge` · `mfa_bypass` · `password_reset` · `user_created` ·
`group_membership_changed` · `privilege_escalation`

**Email and phishing**
`phishing_email_delivered` · `phishing_email_clicked` · `attachment_opened` ·
`credential_harvested` · `email_sent` · `email_forwarding_rule_created`

**Endpoint and malware**
`malware_download` · `malware_execution` · `process_created` ·
`process_injection` · `persistence_established` · `scheduled_task_created` ·
`registry_modified` · `file_created` · `file_modified` · `file_deleted`

**Network**
`dns_query` · `network_connection_allowed` · `network_connection_blocked` ·
`c2_beacon` · `lateral_movement`

**Exfiltration and impact**
`data_staging` · `data_exfiltration` · `log_cleared` · `ransomware_encryption`

**Cloud**
`cloud_api_call` · `cloud_permission_change` · `cloud_resource_created` ·
`cloud_resource_deleted`

**Detection**
`alert_triggered`

### Time offset format

Combine units, always signed: `+0m` · `+30s` · `+16m` · `+2h30m` · `+1d3h15m` ·
`-10s`. Units are `d`, `h`, `m`, `s`. A full ISO-8601 timestamp is also accepted
to pin an event to an exact time.

---

## 22. Configuration and environment variables

Copy `.env.example` to `.env` and edit. `.env` is git-ignored, so keys never get
committed.

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `FORGE_LLM_BACKEND` | `none` | Default AI backend |
| `FORGE_DEFAULT_SEED` | `1337` | Seed when none is given |
| `FORGE_OUTPUT_DIR` | `./output` | Default output directory |
| `FORGE_PLUGINS_DIR` | `./plugins` | Where plugins are discovered |
| `FORGE_SCENARIOS_DIR` | `scenarios` | Web UI scenario directory |
| `FORGE_LOG_LEVEL` | `INFO` | Logging verbosity |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | — | Claude |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — | OpenAI |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | — | Gemini |
| `XAI_API_KEY` / `GROK_MODEL` | — | Grok |
| `OLLAMA_HOST` / `OLLAMA_MODEL` | localhost:11434 | Ollama |

**Do not put quotes around API key values.** Write
`ANTHROPIC_API_KEY=sk-ant-...`, not `ANTHROPIC_API_KEY="sk-ant-..."`.

**Model names go stale.** Provider lineups turn over every few months. If a
command fails with a model-not-found error, check the provider's current model
list and set the model variable in `.env` rather than assuming the built-in
default is still current.

---

## 23. Troubleshooting

**`forge-incident: command not found`**
The virtual environment is not active. Re-run the activation command; your prompt
should show `(.venv)`. If it persists, re-run `pip install -e ".[dev]"`.

**PowerShell: "running scripts is disabled on this system"**
Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then retry.

**A scenario shows as `invalid` in `forge-incident list`**
That is the validator working. Read the error — it names the file and the exact
field. Common causes: an `actor:` or `host:` key that does not exist in the
registries, a typo'd field name (unknown fields are rejected, not ignored), a
malformed MITRE technique ID, or timeline events out of chronological order.

**An LLM backend says "isn't available"**
One of three things: the extra is not installed (`pip install -e ".[claude]"`),
the key is not in `.env` (check you copied `.env.example` to `.env` rather than
editing the example), or for Ollama, `ollama serve` is not running.

**`generate-category` says it requires a real backend**
Correct — `none` cannot invent scenarios. Pass `--llm claude` or another provider.

**Scoring numbers look wrong**
Almost always a seed mismatch. Pass the same `--seed` the student's package was
generated with; timestamps are seeded and response-time scoring depends on them.

**The web UI will not start**
Streamlit is a separate extra: `pip install -e ".[webui]"`.

**A plugin is not loading**
Run `forge-incident plugins` — the specific reason is printed. Files starting
with `_` are skipped by design. The class must subclass `Emitter` or
`PluginEmitter` and be defined in that file rather than imported into it.

**Nothing appears for a log source I expected**
The emitter produces nothing when no event lists it in `log_sources`, and some
emitters also require a matching payload — `palo_alto` and `firewall_syslog` need
a `network` block, the cloud emitters need a `cloud` block, the email emitters
need an `email` block.

**General health check**
Run `pytest` from the project root with the environment active. If all tests
pass, the installation is sound and the problem is specific to the command you
ran. If they fail, that output is the most useful thing to share when asking for
help.

---

## Appendix: file map

```
forge-incident/
├── README.md                     Technical reference
├── GETTING_STARTED.md            Beginner walkthrough
├── COMPLETE_GUIDE.md             This document
├── CONTRIBUTING.md               How to contribute
├── SCENARIO_CATEGORY_TAXONOMY.md The 56 categories and their sources
├── COST_ESTIMATES.md             AI generation cost estimates
├── .env.example                  Configuration template
├── scenarios/                    Scenario definitions
│   ├── phishing_to_exfil.yaml    Bundled example (heavily commented)
│   ├── gcp_key_compromise.yaml   Bundled example (cloud-focused)
│   └── generated/                AI-generated scenarios land here
├── plugins/                      Drop custom log generators here
├── output/                       Generated packages and exports
└── src/forge_incident/           The code
    ├── models.py                 The shared data model
    ├── scenario_loader.py        YAML → validated Scenario
    ├── scenario_categories.py    The category catalog
    ├── packager.py               ZIP assembly
    ├── scoring.py                Grading
    ├── cli.py                    Command-line interface
    ├── emitters/                 The eleven log generators + plugin registry
    ├── siem/                     Splunk, Elastic, Sentinel exporters
    ├── llm/                      Optional AI backends
    └── webui/                    Streamlit interface
```
