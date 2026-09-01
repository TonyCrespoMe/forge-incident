# Scenario Curriculum

The planned set of hand-written bundled scenarios, organized as a teaching
progression across four difficulty tiers. This is the build roadmap: it
records what exists, what's queued, and — importantly — *why each scenario
is on the list*, so the catalog grows deliberately rather than by
accumulating whatever was interesting that week.

**Status key:** ✅ built · 🔨 in progress · ⬜ planned

---

## Design rules for this catalog

**Every scenario must teach something the others don't.** A second phishing
scenario that exercises the same skills as the first is content, not
curriculum. Each entry below names its distinct lesson.

**Difficulty is analytical load, not event count.** See `models.Difficulty`:

| Tier | Shape | Events |
|---|---|---|
| beginner | One clear thread, 1-2 hosts, no red herrings | 6-16 |
| intermediate | Several hosts, at least one benign event to rule out, needs 2+ log sources | 12-28 |
| advanced | Multi-stage chain, defense evasion, evidence must be assembled | 20-45 |
| expert | Adds a deliberate visibility gap and a misleading artifact; correct answer includes what *cannot* be proven | 25-70 |

**Coverage targets.** Across the full catalog every built-in emitter should
be exercised by at least two scenarios, and every OWASP Top 10:2025 category
should appear at least once. Gaps are tracked at the bottom of this file.

**Benign noise is mandatory from intermediate up.** A scenario where every
event is malicious cannot exercise the scoring system's false-positive
metric, and teaches students that everything unusual is an attack. Include
normal logins, legitimate admin work, and routine file access.

---

## Tier 1 — Beginner

Goal: fluency reading a single log format, and the habit of building a
timeline before forming a conclusion.

| # | Scenario | Distinct lesson | Log sources | Status |
|---|---|---|---|---|
| B1 | Phishing to credential harvest | Read an identity log; recognize impossible-travel and a post-compromise inbox rule | okta, outlook_message_trace, email_eml, palo_alto | ✅ |
| B2 | Brute force to successful login | Distinguish a failed-then-succeeded burst from noise; count attempts | linux | ⬜ |
| B3 | Public S3 bucket exposure | Read cloud audit logs; distinguish "misconfigured" from "breached" | aws_cloudtrail | ⬜ |
| B4 | Malicious browser extension | Endpoint basics: process ancestry and a single outbound beacon | windows, palo_alto | ⬜ |
| B5 | Shared account misuse | One credential, several people, one of them shouldn't be there | okta, windows | ⬜ |

## Tier 2 — Intermediate

Goal: the pivot habit — find something in one log, prove or disprove it in
another. Every scenario here contains benign activity that must be ruled out.

| # | Scenario | Distinct lesson | Log sources | Status |
|---|---|---|---|---|
| I1 | Phishing to data exfiltration | Cross-source correlation via a shared hash and IP | email_eml, outlook_message_trace, palo_alto, windows | ✅ |
| I2 | Insider USB data theft | Malicious intent inside *authorized* access; benign-vs-malicious discrimination | windows | ✅ |
| I3 | Business email compromise | Follow the money: a hidden inbox rule and a redirected invoice | outlook_message_trace, email_eml, azure_activity | ⬜ |
| I4 | SQL injection to database dump | Read web logs; spot the anomalous path, not the anomalous agent | iis, palo_alto | ⬜ |
| I5 | Compromised cloud VM cryptomining | Cost/CPU anomaly as the initial signal; work backwards to weak SSH | aws_cloudtrail, linux | ⬜ |
| I6 | Malicious OAuth consent grant | Access that survives a password reset; token vs. password | azure_activity, okta | ⬜ |

## Tier 3 — Advanced

Goal: reconstruct a multi-stage chain including defense evasion, and scope
the compromise correctly.

| # | Scenario | Distinct lesson | Log sources | Status |
|---|---|---|---|---|
| A1 | Leaked service account key to cloud exfiltration | Cloud logs record the *credential*, never the human | gcp_audit, linux | ✅ |
| A2 | Stolen developer credentials to AWS | Developer credential as the front door; CI/CD as the pivot | aws_cloudtrail, linux, palo_alto | ✅ |
| A3 | Web shell to domain controller compromise | Encoded commands; exfil ≠ dump; scope a DC compromise | iis, windows | ✅ |
| A4 | Kerberoasting to lateral movement | Offline cracking leaves almost no trace; find the ticket request | windows | ⬜ |
| A5 | Supply chain: poisoned CI pipeline | Trust boundary is the build, not the code | linux, aws_cloudtrail | ⬜ |
| A6 | Living-off-the-land admin abuse | Every tool used is signed and legitimate; only the pattern is wrong | windows, crowdstrike | ⬜ |

## Tier 4 — Expert

Goal: work an incident where the evidence is incomplete and partly
misleading, and say so precisely. Every scenario in this tier includes a
deliberate visibility gap and at least one misleading artifact.

| # | Scenario | Distinct lesson | Log sources | Status |
|---|---|---|---|---|
| E1 | Ransomware: intrusion to encryption | Multi-day dwell; reconstruct the pre-encryption staging nobody looked at | windows, crowdstrike, firewall_syslog, palo_alto | ✅ |
| E2 | Hybrid identity compromise (on-prem to cloud) | Trust relationship abuse; forged tokens that look legitimate | windows, azure_activity, okta | ⬜ |
| E3 | Insider with admin rights covering tracks | Log clearing; prove absence from surrounding evidence | windows, linux | ⬜ |
| E4 | Multi-cloud lateral movement | One identity, three providers, no single log tells the story | aws_cloudtrail, azure_activity, gcp_audit | ⬜ |
| E5 | Slow-and-low API data scraping | Volume over months, individually unremarkable requests | iis, palo_alto | ⬜ |

---

## OWASP Top 10:2025 coverage

| Category | Covered by | Status |
|---|---|---|
| A01 Broken Access Control | I4, E5 | ⬜ |
| A02 Security Misconfiguration | B3, I5 | ⬜ |
| A03 Software Supply Chain Failures | A5 | ⬜ |
| A04 Cryptographic Failures | — | **gap** |
| A05 Injection | I4 | ⬜ |
| A06 Insecure Design | E5 | ⬜ |
| A07 Authentication Failures | B1 ✅, B2, I6 | partial |
| A08 Software/Data Integrity Failures | A5 | ⬜ |
| A09 Logging & Alerting Failures | E1, E3 | ⬜ |
| A10 Mishandling of Exceptional Conditions | — | **gap** |

Two genuine gaps. A04 and A10 are both hard to express in log data — a
cryptographic failure or a fail-open error usually leaves no distinctive
trace in the sources this tool models. Rather than force them, they're
recorded here as known gaps; the `generate-category` taxonomy covers both
for anyone who wants to attempt one.

## Emitter coverage

| Emitter | Scenarios using it (built + planned) | Notes |
|---|---|---|
| windows | I1, I2, A3, A4, A6, E1, E2, E3, B4, B5 | well covered |
| linux | A1, A2, A5, B2, E3, I5 | well covered |
| iis | A3, I4, E5 | added recently |
| aws_cloudtrail | A2, A5, B3, I5, E4 | covered |
| azure_activity | I3, I6, E2, E4 | **not yet used by any BUILT scenario** |
| gcp_audit | A1, E4 | covered |
| okta | B1, B5, I6, E2 | covered |
| crowdstrike | A6, E1 | covered |
| firewall_syslog | E1 | covered |
| palo_alto | I1, A2, B4, I4, E5 | well covered |
| outlook_message_trace | I1, B1, I3 | covered |
| email_eml | I1, B1, I3 | covered |

Eleven of the twelve built-in emitters are exercised by at least one BUILT
scenario. The exception is `azure_activity`, which is implemented and tested
but appears only in planned rows — I3 (business email compromise) and I6
(malicious OAuth consent grant) are the next two scenarios and both use it.

---

## Relationship to `generate-category`

This catalog is **hand-written reference material**: vetted, deliberately
designed, and safe to hand a student without review. It is not trying to be
exhaustive.

For breadth, `forge-incident generate-category` already offers 56 categories
across 12 domains (see `SCENARIO_CATEGORY_TAXONOMY.md`) and will invent a
fresh scenario for any of them. The division of labour:

- **Hand-written (this file):** the teaching backbone. Every scenario has a
  reason to exist, a verified answer key, and tests pinning its mechanics.
- **Generated (`generate-category`):** unlimited practice volume once a
  student has worked the reference set, flagged for instructor review.

Once the randomized-cast feature lands, each hand-written scenario also
yields unlimited unique variants at the same difficulty, which changes the
economics of this list considerably — 24 well-built scenarios becomes an
effectively unbounded exercise library.
