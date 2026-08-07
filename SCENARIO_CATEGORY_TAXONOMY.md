# ForgeIncident Scenario Category Taxonomy

Researched from OWASP's maintained Top 10 projects, MITRE ATT&CK, and cloud-provider /
government incident-response guidance, to source a category menu for the "generate a
new scenario" feature. Each entry translates a named risk/vulnerability into an
investigation *premise* — a story with a beginning (initial access), middle
(actions), and end (impact) that a training timeline can be built around.

---

## 1. Web application layer — OWASP Top 10:2025

Source: [owasp.org/Top10/2025](https://owasp.org/Top10/2025/) (released Jan 2026, current version)

| OWASP category | Scenario premise |
|---|---|
| A01 Broken Access Control | IDOR/privilege escalation — low-priv user manipulates an object reference to reach admin data or another tenant's records |
| A02 Security Misconfiguration | Exposed admin panel, default creds, or debug endpoint left open, found and abused by an opportunistic scanner |
| A03 Software Supply Chain Failures | A compromised or typosquatted dependency ships malicious code into production (new category, highest 2025 incidence) |
| A04 Cryptographic Failures | Weak/legacy encryption or hardcoded key allows interception or offline decryption of sensitive data |
| A05 Injection | SQL/command injection in a public form leads to database dump and exfiltration |
| A06 Insecure Design | Business-logic abuse (e.g., discount-code enumeration, workflow bypass) with no clean technical "vulnerability" to patch |
| A07 Authentication Failures | Credential stuffing or session-fixation leads to account takeover |
| A08 Software/Data Integrity Failures | Unsigned auto-update or CI artifact tampered with, deployed as trusted |
| A09 Security Logging & Alerting Failures | Attacker dwells for weeks because failed logins/anomalies were never alerted on — investigation reconstructs the gap |
| A10 Mishandling of Exceptional Conditions | Error-handling/fail-open bug lets an attacker bypass a control during an edge-case failure |

## 2. API layer — OWASP API Security Top 10 (2023)

Source: [owasp.org/API-Security/editions/2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

Broken Object Level Authorization (BOLA/IDOR on an API), Broken Authentication, Broken
Object Property Level Authorization (excessive data exposure / mass assignment),
Unrestricted Resource Consumption (no rate limiting → scraping or cost-exhaustion),
Broken Function Level Authorization, Unrestricted Access to Sensitive Business Flows
(bot abuse of a checkout/signup flow), Security Misconfiguration, Improper Input
Validation, Improper Inventory Management (a forgotten "shadow" API version left
unpatched), Unsafe Consumption of APIs (trusting a third-party API's response
uncritically). Good scenario premise: an internal API missing object-level auth checks
lets a customer enumerate other customers' records via sequential IDs.

## 3. CI/CD & software supply chain — OWASP Top 10 CI/CD Security Risks

Source: [owasp.org/www-project-top-10-ci-cd-security-risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

Insufficient Flow Control Mechanisms, Inadequate Identity/Access Management, Dependency
Chain Abuse, **Poisoned Pipeline Execution**, Insufficient Pipeline-Based Access
Control, Insufficient Credential Hygiene, Insecure System Configuration, Ungoverned
Use of 3rd-Party Services, Improper Artifact Integrity Validation, Insufficient
Logging/Visibility. Modeled on real breaches (SolarWinds, Codecov, the npm
ua-parser-js/coa/rc compromises). Scenario premise: a leaked CI runner token lets an
attacker inject a malicious build step that backdoors the release artifact —
essentially a scoped-down SolarWinds.

## 4. AI/LLM application layer — OWASP Top 10 for LLM Applications (2025)

Source: [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

Prompt Injection, Sensitive Information Disclosure, Supply Chain, Data/Model
Poisoning, Improper Output Handling, Excessive Agency, System Prompt Leakage, Vector/
Embedding Weaknesses, Misinformation, Unbounded Consumption. Timely and distinct from
everything else on this list — no existing bundled scenario touches it. Scenario
premise: a support chatbot with excessive tool permissions is prompt-injected via a
crafted support ticket into exfiltrating other customers' data through a tool call it
shouldn't have had access to.

## 5. Mobile — OWASP Mobile Top 10 (2024)

Source: [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10/)

Improper Credential Usage, Inadequate Supply Chain Security, Insecure Auth/
Authorization, Insufficient Input/Output Validation, Insecure Communication,
Inadequate Privacy Controls, Insufficient Binary Protections, Security
Misconfiguration, Insecure Data Storage, Insufficient Cryptography. Scenario premise:
a corporate BYOD app stores an auth token in plaintext local storage; a lost/stolen
device (or a malicious sideloaded app reading shared storage) leads to account
compromise.

---

## 6. Cloud platforms (grounded in MITRE ATT&CK Enterprise + provider IR guidance)

MITRE's Enterprise matrix explicitly covers Windows, macOS, Linux, Identity Provider,
SaaS, and IaaS (AWS/Azure/GCP) as first-class platforms — [attack.mitre.org/matrices/enterprise](https://attack.mitre.org/matrices/enterprise/).
That's the natural backbone for tagging events (ForgeIncident's `mitre` field already
does this), so every category below maps cleanly onto it.

**AWS** — source: [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- Leaked/long-lived IAM access key committed to a public repo → used for lateral access
- Public S3 bucket exposure and mass download/exfiltration
- SSRF against an EC2 instance to steal instance-metadata credentials (Capital One-pattern)
- CloudTrail disabled or tampered with as a defense-evasion step mid-intrusion
- Compromised EC2 used for cryptomining or as a pivot point

**Azure / Entra ID** — source: [Microsoft token theft playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook), [Microsoft IR blog](https://www.microsoft.com/en-us/security/blog/2023/12/05/microsoft-incident-response-lessons-on-preventing-cloud-identity-compromise/)
- AiTM phishing steals a session token, bypassing MFA ("pass-the-cookie")
- Malicious OAuth app / consent-phishing grants an attacker persistent API access
- Compromised CI/CD service principal exfiltrates a token via `az` CLI in a pipeline
- Entra Connect / AD FS token-signing certificate theft used to forge tokens

**GCP** — source: [Google Cloud Storage threat model](https://docs.cloud.google.com/docs/security/threat-model/storage-threat-model), already the basis of the bundled `gcp_key_compromise` scenario
- Leaked service-account key (bundled scenario)
- Misconfigured public Cloud Storage bucket
- Overly permissive IAM role grants used for lateral movement between projects
- Audit logging disabled/altered to cover tracks

## 7. On-prem endpoints and servers (SANS/CISA-grounded)

Source: CISA/NSA/Five Eyes [joint Active Directory guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/detecting-and-mitigating-active-directory-compromises), [CISA Akira ransomware advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a), SANS FOR508/FOR518 course scope

**Windows client/server**
- Active Directory compromise via Kerberoasting/AS-REP roasting → cracked service-account password
- LSASS credential dumping → lateral movement via pass-the-hash
- Ransomware deployment through a compromised RDP/VPN endpoint (Akira-pattern: initial access → Kerberoasting → encryption)
- DCSync / Golden Ticket abuse for domain-wide persistence
- Group Policy Object abuse for mass lateral movement

**Linux client/server**
- SSH brute-force or stolen key → server compromise (closely related to the bundled `phishing_to_exfil`)
- Public-facing web server compromised via injection → web shell dropped → cron/systemd persistence
- Privilege escalation via a misconfigured sudoers entry or SUID binary

**macOS**
- Malicious/unsigned app via fake-update social engineering → LaunchAgent persistence
- Keychain credential theft
- TCC/Gatekeeper bypass to access sensitive data (contacts, screen recording) undetected

## 8. Cross-cutting categories (not owned by any single list, but core DFIR training staples)

- Phishing → malware → lateral movement → exfiltration (bundled `phishing_to_exfil`)
- Business email compromise / mailbox-rule abuse for wire fraud
- Insider threat: departing employee mass-downloads/exfiltrates data before offboarding
- Removable media (USB) introduces malware into an air-gapped or segmented network
- End-to-end ransomware: initial access → staging → encryption → extortion note

---

## Assessment

This is a good move, and better grounded than my first pass. A few notes:

**Scale changed.** My earlier proposal was a flat ~10-item menu. Combining everything
above gives roughly 35-40 named categories across 8 domains — genuinely comprehensive,
matching what a real SOC/DFIR analyst triages across app, API, CI/CD, AI, mobile, three
clouds, and three OS families. That's a much better training curriculum, but it changes
the UI: a flat list of 40 is unwieldy. **Recommend a two-level picker** — pick a domain
first (Web App / API / CI-CD & Supply Chain / AI-LLM App / Mobile / AWS / Azure / GCP /
Windows Enterprise / Linux-Unix / macOS / Cross-Cutting), then a specific category
within it, then difficulty.

**MITRE ATT&CK as the unifying layer.** Every category above sits naturally on the
Enterprise ATT&CK matrix, which is exactly what ForgeIncident's `mitre` field on each
event already expects. That's a real design win: the LLM generation prompt can require
"pick real ATT&CK technique IDs consistent with this category" as a hard constraint,
which is checkable (technique ID format/validity) even before getting into the harder
semantic-consistency problem discussed earlier.

**Sequencing recommendation.** Don't try to support all ~40 on day one. Ship a v1 slice
that's diverse but small (one or two per domain — maybe 12-15 categories), validate the
generation pipeline works well and stays consistent on those, then expand the menu
category-by-category. Adding a category later is just adding a menu entry + a
short category-specific prompt fragment; it doesn't touch the generation/validation
machinery.

This taxonomy work itself carries zero implementation risk — it's just reference data.
The open question is still the one from before: prompting strategy and the validate/
retry loop for the actual YAML generation. Happy to start building the v1 menu (I'd
suggest: A05 Injection, A01 Broken Access Control, AI/LLM prompt injection, AWS leaked
IAM key, Azure AiTM token theft, GCP bucket exposure — already bundled, Windows AD
Kerberoasting-to-ransomware, Linux SSH-to-webshell, macOS fake-update malware, BEC,
insider threat, CI/CD poisoned pipeline) plus the category config file, whenever you
want to move on it.
