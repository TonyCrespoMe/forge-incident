# Design Constraints

Rules this project must hold to, and the reasoning behind them.

This file exists because some of these constraints **cannot be enforced by a
test**. A contributor — human or AI — who has not read this file can violate
them while every test still passes. If you are picking this project up cold,
read this before writing a scenario or touching the generator.

Constraints that *are* mechanically enforced are listed here anyway, because
the test tells you *what* broke and this file tells you *why it matters*.

---

## 1. Provenance: no borrowed identifiers

**Rule.** No identifier in this repository may be copied from any third
party's material — a hiring challenge, a vendor CTF, a commercial course, a
published incident report, or another project's sample data.

"Identifier" means the literal strings a reader could match on:

- hostnames, usernames, email addresses, employee IDs
- IP addresses, domain names, URL paths
- file names, service names, registry keys
- file hashes, process IDs, ticket or case numbers
- organization names

**Attack *patterns* are explicitly fine.** Web shell to credential dump to
domain controller is how intrusions actually work; it belongs to the field,
not to whoever last wrote an exercise about it. Reproducing the *technique*
is the entire point of this tool. Reproducing someone's *strings* is not,
and creates an attribution problem this project has no reason to accept.

**Not testable.** A test cannot know a hash was copied rather than invented.
This one runs on discipline. When adapting a pattern from material you have
read, generate a fresh cast from scratch and diff the result against the
source before committing.

**If you ever suspect a leak**, the check is a repo-wide literal scan:

```bash
grep -rn --include='*.yaml' --include='*.py' --include='*.md' \
     --include='*.toml' -F -f suspect_strings.txt .
```

Run it across `.yaml`, `.py`, `.md`, and `.toml`. Free-text fields —
`description`, `command_line`, `student_briefing`, answer-key prose — are
where borrowed strings survive a careless find-and-replace, because they
are prose rather than structured fields.

---

## 2. Reserved address and domain space

**Rule.** Fictional infrastructure uses ranges the standards bodies reserved
for exactly this purpose:

| Kind | Use | Reserved by |
|---|---|---|
| Domains | `.example`, `.test`, `.invalid` | RFC 2606 |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 |
| IPv6 | `2001:db8::/32` | RFC 3849 |
| Internal IPv4 | `10/8`, `172.16/12`, `192.168/16` | RFC 1918 |

**Why.** A published exercise that labels a routable address as "the
attacker" is training analysts to associate a real network with an attack
that never happened. That address belongs to someone. Reserved space costs
nothing and carries no such claim.

**Enforced for domains** by `tests/test_curriculum.py::
test_organizations_use_the_reserved_example_tld`, with a documented
exemption for provider-dictated service-identity formats (a GCP service
account genuinely does look like `name@project.iam.gserviceaccount.com`, and
faking that would teach the wrong shape).

**Not currently enforced for IPs — and the repo does not yet comply.**
See "Known open issues" below.

---

## 3. Instructor content never reaches the student

**Rule.** `Scenario.description`, `Event.description`, and the entire
`answer_key` are instructor-only. They must never appear in any rendered
log line, SIEM export, or student bundle.

**Why.** These fields carry the solution. `Event.description` typically
opens with `BENIGN.` or names the technique outright. One leak into an
emitter turns an exercise into a worksheet with the answers printed on it.

**Enforced** in both output paths — `tests/test_siem.py::
test_siem_exports_never_leak_instructor_narrative` and the equivalent check
over the raw emitters. When adding an emitter, render only from the payload
models (`network`, `file`, `process`, `email`, `cloud`, `http`, `service`)
and the event's structural fields. Never from `description`.

**Documented exception:** SIEM exports *do* include ATT&CK technique IDs.
An export without them cannot be used to validate detection content, which
is the reason to produce one. This is deliberate and tested for.

---

## 4. LLMs plan; Python renders

**Rule.** Every byte of log output is produced by deterministic Python from
the shared `Scenario` / `Event` model. A language model may author a
*scenario definition* (`llm/scenario_generator.py`) or *plan* one
(`plan_scenario`). It never writes a log line.

**Why.** Two reasons, and the second is the one people underestimate:

1. **Format fidelity.** Real log formats have quirks — IIS escapes spaces in
   the user-agent as `+` and writes `-` for absent fields; Windows records a
   7045 whenever a service is installed regardless of how an analyst later
   classifies the event. A model asked to "write some IIS logs" produces
   something that *looks* right and fails the moment a student parses it
   with a real tool.
2. **Reproducibility.** Two students working the same `scenario_id` must be
   able to compare findings line by line. If a model generated the lines,
   they cannot.

**Corollary — determinism is a feature, not an implementation detail.** All
randomness derives from `seed` through `derive_rng` / `stable_hex_id` /
`stable_int_id`. Same seed, byte-identical bundle, forever. Never call
`random` or `uuid4` directly in an emitter, and never put a wall-clock
timestamp in rendered output.

---

## 5. Difficulty is analytical load, not event count

**Rule.** Tier reflects how hard the *reasoning* is, not how long the
timeline is. The floors in `tests/test_curriculum.py` are sanity checks
against a scenario claiming a tier it obviously cannot support — they are
not a rubric to build toward.

**Why this is written down.** The failure mode is real and already happened
once during development: an event-count minimum set too high would have
forced a 9-event scenario to be padded to 20 to keep its "advanced" label.
The padding would have made it *worse* — more to read, nothing more to
work out. `gcp_key_compromise` is short and genuinely advanced because its
lesson (cloud logs identify the credential, never the human) is subtle.

**Two tier-specific requirements that are enforced:**

- **Intermediate and above must contain benign events.** Without them the
  precision metric is unmeasurable and the exercise implicitly teaches that
  everything unusual is an attack. A scenario where flagging *everything*
  scores 100% is broken.
- **Expert must contain a real visibility gap** — a log source that goes
  silent mid-timeline while events on that host continue — and a misleading
  artifact. Otherwise "expert" just means "long."

A misleading artifact should be **disarmable by evidence, not by intuition**.
If a decoy is a high-volume backup job, include the previous night's
identical job so a student can *prove* it is routine rather than guess.

---

## 6. Every scenario teaches something no other scenario teaches

**Rule.** Each entry in `SCENARIO_CURRICULUM.md` names its distinct lesson.
A new scenario that exercises the same skills as an existing one is content,
not curriculum, and should be rejected or merged.

**Not testable** — this is an editorial judgment. It is the reason the
curriculum file records *why* each scenario is on the list rather than just
listing them.

---

## 7. Staying current

**Rule.** The threat landscape moves faster than a hand-written catalog
can track by accident. A scenario that was representative when it was
written reads as dated eighteen months later — not because it becomes
*wrong*, but because it stops being what a real investigation looks like
first. "Always up to date" is not a property a training tool acquires
once; it's a maintenance habit, and it needs a trigger or it quietly
lapses like any other maintenance habit does.

**Practice.** Once or twice a year — or whenever a scenario feels like it
might have aged — check the catalog's initial-access and persistence
techniques against that cycle's major reports (Verizon DBIR, Mandiant
M-Trends, CrowdStrike Global Threat Report, Microsoft's threat-intel
blog). Two questions per check: is anything in the catalog now a
minority technique rather than a common one, and is anything *missing*
that's become common enough to matter. `aitm_session_hijack.yaml` is the
first scenario added this way rather than from the original curriculum
plan — see `SCENARIO_CURRICULUM.md`'s A7 entry for the reports that
prompted it and the reasoning for why it was a genuine gap rather than
just a new coat of paint on an existing lesson.

**Not testable** — like constraint 6, this is an editorial judgment, not
something a unit test can check. What *is* enforceable going forward:
give a scenario added this way a note in the curriculum explaining what
prompted it, so five years from now someone can tell "written from the
original plan" apart from "added because the field changed," and audit
whether the reasoning still holds.

**Anti-pattern to avoid.** This is not a license to chase every headline.
A technique earns a scenario when multiple independent reports converge
on it as a *trend*, not when one write-up describes an interesting
one-off. The bar is the same as constraint 6's: it has to teach something
the catalog doesn't already teach, threat-landscape relevance is a reason
to prioritize which gap to fill next, not a reason to skip asking whether
it's actually a gap.

---

## Open design: randomized cast

**Goal.** Let one hand-written scenario yield unlimited variants at the same
difficulty, so a class of twenty students each gets different names, hosts,
and addresses while working an identical analytical problem.

**Approach.** A seeded `CastProfile` substituted at the `Scenario` level
*after* validation, followed by a verification pass asserting that no
original cast value survives anywhere in the rendered output.

**The trap, stated explicitly because it is not obvious.** Identifiers are
not confined to structured fields. They are embedded in free text —
`description`, `command_line`, `student_briefing`, and answer-key prose.
Substituting only the structured fields produces a bundle where the logs say
one thing and the instructor guide says another. The scenario would still
load, still pass every existing test, and be quietly useless.

The verification pass is therefore **not optional polish — it is the
feature**. Any implementation that substitutes without proving absence of
the original values should be considered incomplete.

---

## Known open issues

**Routable IPs used as attacker infrastructure.** Constraint 2 is not yet
met. Six real, routable addresses currently appear as attacker or C2
infrastructure:

| Address | Used in |
|---|---|
| `45.9.148.32` | `phishing_credential_harvest.yaml` |
| `193.27.14.86` | `webshell_to_dc_compromise.yaml` |
| `45.132.192.77`, `91.219.236.18` | `stolen_dev_credentials_aws.yaml` |
| `176.53.14.209` | `ransomware_full_chain.yaml` |
| `185.220.101.47` | `tests/`, `COMPLETE_GUIDE.md` |

These should move into RFC 5737 space. The three reserved `/24`s give 762
usable addresses, which is far more than this catalog needs. Note that
`185.220.101.47` is referenced by `tests/test_siem.py` and by worked
examples in `COMPLETE_GUIDE.md`, so that change touches docs and tests too.

Separately, `140.82.121.4` (GitHub) and `185.199.108.153` (GitHub Pages)
appear as *legitimate destinations*. These are arguably fine — they are the
real service being contacted for a real reason — but the safer convention is
to use reserved space uniformly and let the hostname carry the meaning.

**No enforcement test exists yet.** A `test_scenarios_use_reserved_ip_space`
check, mirroring the existing domain test, would prevent regression. It
should be added in the same change that fixes the addresses, not before.
