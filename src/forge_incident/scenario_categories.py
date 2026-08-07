"""Scenario category taxonomy for LLM-driven "generate a new scenario" flow.

Every category here is a short, well-documented investigation *premise* —
grounded in OWASP's maintained Top 10 projects, MITRE ATT&CK's Enterprise
platform coverage, and cloud-provider / government incident-response
guidance (see SCENARIO_CATEGORY_TAXONOMY.md at the repo root for full
sourcing). `llm/scenario_generator.py` turns a chosen category + difficulty
into a prompt asking a real LLM backend to write a brand-new scenario YAML
around that premise; nothing in *this* module talks to an LLM or invents
any scenario content itself — it is pure, static reference data, organized
into domains for a two-level CLI picker (`forge-incident categories`,
`forge-incident generate-category`).

`primary_log_sources` are hints for the generation prompt (which
`LogSource` values, from `models.LogSource`, make sense for this
category's story) — not a hard constraint; scenarios needing to combine
sources (e.g. an email lure that lands on an endpoint) commonly will.

A few domains render through an emitter that is a documented
*approximation* rather than a native format for that platform (see each
domain's `notes`): ForgeIncident has no dedicated macOS Unified Log
emitter, so macOS categories render endpoint telemetry through the
`linux` (syslog/auth-log) emitter, which is a reasonable Unix-family
approximation but not byte-for-byte `log show` output. AWS and Azure
categories DO get native, purpose-built emitters (`aws_cloudtrail`,
`azure_activity`), added alongside this taxonomy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "Domain",
    "ScenarioCategory",
    "DOMAINS",
    "CATEGORIES",
    "domain_ids",
    "get_domain",
    "categories_in_domain",
    "get_category",
    "all_category_ids",
]


@dataclass(frozen=True)
class Domain:
    id: str
    name: str
    description: str


@dataclass(frozen=True)
class ScenarioCategory:
    id: str
    domain: str
    name: str
    summary: str
    suggested_tactics: tuple[str, ...] = field(default_factory=tuple)
    suggested_techniques: tuple[str, ...] = field(default_factory=tuple)
    primary_log_sources: tuple[str, ...] = field(default_factory=tuple)
    source: str = ""
    notes: str = ""


# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------

DOMAINS: tuple[Domain, ...] = (
    Domain("web_app", "Web Application", "OWASP Top 10:2025 web application risks."),
    Domain("api", "API Security", "OWASP API Security Top 10 (2023)."),
    Domain(
        "cicd_supply_chain",
        "CI/CD & Software Supply Chain",
        "OWASP Top 10 CI/CD Security Risks.",
    ),
    Domain("ai_llm", "AI / LLM Applications", "OWASP Top 10 for LLM Applications (2025)."),
    Domain("mobile", "Mobile", "OWASP Mobile Top 10 (2024)."),
    Domain("aws", "AWS Cloud", "Common AWS incident patterns; renders via aws_cloudtrail."),
    Domain("azure", "Azure / Entra ID", "Common Azure/Entra incident patterns; renders via azure_activity."),
    Domain("gcp", "Google Cloud Platform", "Common GCP incident patterns; renders via gcp_audit."),
    Domain(
        "windows_enterprise",
        "Windows Client & Server / Active Directory",
        "CISA/NSA Five-Eyes AD guidance and SANS FOR508-scope Windows incidents.",
    ),
    Domain("linux_unix", "Linux / Unix Client & Server", "SANS FOR508-scope Linux/Unix incidents."),
    Domain("macos", "macOS", "SANS FOR518-scope macOS incidents (renders via the linux syslog emitter)."),
    Domain(
        "cross_cutting",
        "Cross-Cutting",
        "DFIR staples not owned by a single framework: phishing, BEC, insider threat, ransomware.",
    ),
)

_DOMAIN_BY_ID = {d.id: d for d in DOMAINS}


def domain_ids() -> list[str]:
    return [d.id for d in DOMAINS]


def get_domain(domain_id: str) -> Domain:
    try:
        return _DOMAIN_BY_ID[domain_id]
    except KeyError as exc:
        raise KeyError(f"Unknown domain {domain_id!r}. Known domains: {domain_ids()}") from exc


# --------------------------------------------------------------------------
# Categories
# --------------------------------------------------------------------------

CATEGORIES: tuple[ScenarioCategory, ...] = (
    # -- Web application (OWASP Top 10:2025) --------------------------------
    ScenarioCategory(
        id="web-a01-broken-access-control",
        domain="web_app",
        name="Broken Access Control (IDOR)",
        summary=(
            "A low-privileged authenticated user manipulates an object reference (e.g. a "
            "sequential account/order ID) in a web application to reach another tenant's "
            "records or an admin-only function, discovered via an anomalous access pattern "
            "in web traffic logs before escalating to a bulk data export."
        ),
        suggested_tactics=("Discovery", "Collection", "Exfiltration"),
        suggested_techniques=("T1213 Data from Information Repositories", "T1530 Data from Cloud Storage Object"),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A01",
    ),
    ScenarioCategory(
        id="web-a02-security-misconfiguration",
        domain="web_app",
        name="Security Misconfiguration",
        summary=(
            "An exposed admin console or debug endpoint left with default credentials is "
            "found by an opportunistic scanner, then used to upload a web shell and gain "
            "code execution on the application server."
        ),
        suggested_tactics=("Reconnaissance", "Initial Access", "Execution"),
        suggested_techniques=("T1595 Active Scanning", "T1190 Exploit Public-Facing Application"),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A02",
    ),
    ScenarioCategory(
        id="web-a03-software-supply-chain",
        domain="web_app",
        name="Software Supply Chain Failure",
        summary=(
            "A compromised or typosquatted open-source dependency is pulled into a build, "
            "shipping malicious code into production that exfiltrates environment secrets "
            "on startup."
        ),
        suggested_tactics=("Resource Development", "Initial Access", "Exfiltration"),
        suggested_techniques=("T1195.001 Compromise Software Dependencies and Development Tools",),
        primary_log_sources=("linux", "palo_alto"),
        source="OWASP Top 10:2025 A03",
    ),
    ScenarioCategory(
        id="web-a04-cryptographic-failures",
        domain="web_app",
        name="Cryptographic Failures",
        summary=(
            "A weak/legacy encryption scheme or a hardcoded key found in an exposed config "
            "file lets an attacker decrypt intercepted session tokens offline, leading to "
            "account takeover without ever touching the login form."
        ),
        suggested_tactics=("Credential Access", "Initial Access"),
        suggested_techniques=("T1552 Unsecured Credentials", "T1552.001 Credentials In Files"),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A04",
    ),
    ScenarioCategory(
        id="web-a05-injection",
        domain="web_app",
        name="Injection (SQLi)",
        summary=(
            "SQL injection in a public-facing search or login form is used to dump the "
            "customer database, then automated tooling exfiltrates the data over HTTP."
        ),
        suggested_tactics=("Initial Access", "Collection", "Exfiltration"),
        suggested_techniques=("T1190 Exploit Public-Facing Application", "T1041 Exfiltration Over C2 Channel"),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A05",
    ),
    ScenarioCategory(
        id="web-a06-insecure-design",
        domain="web_app",
        name="Insecure Design (business logic abuse)",
        summary=(
            "A workflow/business-logic flaw with no clean technical vulnerability to patch "
            "— e.g. discount-code enumeration or a negative-quantity checkout bypass — is "
            "abused at scale for financial fraud, discovered only through anomaly detection "
            "on order patterns."
        ),
        suggested_tactics=("Discovery", "Collection", "Impact"),
        suggested_techniques=("T1204 User Execution",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A06",
    ),
    ScenarioCategory(
        id="web-a07-authentication-failures",
        domain="web_app",
        name="Authentication Failures (credential stuffing)",
        summary=(
            "A credential-stuffing attack using a leaked password list against a login "
            "endpoint succeeds on a handful of reused-password accounts, leading to "
            "session-fixation-assisted account takeover."
        ),
        suggested_tactics=("Credential Access", "Initial Access"),
        suggested_techniques=("T1110.004 Credential Stuffing",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A07",
    ),
    ScenarioCategory(
        id="web-a08-software-data-integrity",
        domain="web_app",
        name="Software or Data Integrity Failure",
        summary=(
            "An unsigned auto-updater or CI-produced deployment artifact is swapped for a "
            "backdoored version between build and release, and the application trusts it "
            "without verifying integrity."
        ),
        suggested_tactics=("Initial Access", "Persistence", "Execution"),
        suggested_techniques=("T1195.002 Compromise Software Supply Chain",),
        primary_log_sources=("linux", "windows"),
        source="OWASP Top 10:2025 A08",
    ),
    ScenarioCategory(
        id="web-a09-logging-alerting-failures",
        domain="web_app",
        name="Security Logging & Alerting Failure",
        summary=(
            "An attacker dwells for weeks inside an application's user data because failed "
            "logins and anomalous API usage were never wired to any alert; the "
            "investigation has to reconstruct the entire dwell-time gap from raw historical "
            "logs reviewed only after a customer complaint."
        ),
        suggested_tactics=("Defense Evasion", "Discovery"),
        suggested_techniques=("T1070 Indicator Removal",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A09",
    ),
    ScenarioCategory(
        id="web-a10-mishandling-exceptional-conditions",
        domain="web_app",
        name="Mishandling of Exceptional Conditions",
        summary=(
            "A fail-open bug in an authentication or payment-validation flow — triggered by "
            "a malformed request that the application mishandles — lets an attacker bypass "
            "MFA or payment checks during the error condition."
        ),
        suggested_tactics=("Defense Evasion", "Initial Access"),
        suggested_techniques=("T1548 Abuse Elevation Control Mechanism",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10:2025 A10",
    ),
    # -- API Security (OWASP API Security Top 10:2023) ----------------------
    ScenarioCategory(
        id="api-bola",
        domain="api",
        name="Broken Object Level Authorization (BOLA)",
        summary=(
            "An internal REST API missing per-object authorization checks lets an "
            "authenticated customer enumerate sequential resource IDs and read other "
            "customers' records, discovered via a spike in 200-status requests against "
            "IDs the caller never legitimately owned."
        ),
        suggested_tactics=("Discovery", "Collection"),
        suggested_techniques=("T1213 Data from Information Repositories",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP API Security Top 10:2023 API1",
    ),
    ScenarioCategory(
        id="api-broken-authentication",
        domain="api",
        name="Broken Authentication (forged JWT)",
        summary=(
            "A JWT signature-verification flaw (e.g. accepting the 'none' algorithm) lets "
            "an attacker forge a token claiming admin privileges, granting direct access to "
            "privileged API endpoints without ever authenticating normally."
        ),
        suggested_tactics=("Credential Access", "Privilege Escalation"),
        suggested_techniques=("T1552 Unsecured Credentials", "T1548 Abuse Elevation Control Mechanism"),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP API Security Top 10:2023 API2",
    ),
    ScenarioCategory(
        id="api-excessive-data-exposure",
        domain="api",
        name="Broken Object Property Level Authorization",
        summary=(
            "A mass-assignment flaw lets an ordinary API consumer set an `is_admin`-style "
            "field they were never meant to control, silently granting themselves elevated "
            "privileges the application's UI never exposes."
        ),
        suggested_tactics=("Privilege Escalation",),
        suggested_techniques=("T1078 Valid Accounts",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP API Security Top 10:2023 API3",
    ),
    ScenarioCategory(
        id="api-unrestricted-resource-consumption",
        domain="api",
        name="Unrestricted Resource Consumption",
        summary=(
            "A public API with no rate limiting is scraped end-to-end by an automated "
            "client, exfiltrating an entire user directory over days while blending in "
            "with normal traffic volume."
        ),
        suggested_tactics=("Collection", "Exfiltration"),
        suggested_techniques=("T1213 Data from Information Repositories",),
        primary_log_sources=("palo_alto",),
        source="OWASP API Security Top 10:2023 API4",
    ),
    ScenarioCategory(
        id="api-unsafe-api-consumption",
        domain="api",
        name="Unsafe Consumption of APIs",
        summary=(
            "An internal service trusts a third-party API's response body uncritically; "
            "when the upstream is compromised (or spoofed via DNS/SSRF), the malicious "
            "response is used to inject data or commands into the internal system."
        ),
        suggested_tactics=("Initial Access", "Execution"),
        suggested_techniques=("T1190 Exploit Public-Facing Application",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP API Security Top 10:2023 API10",
    ),
    # -- CI/CD & software supply chain (OWASP Top 10 CI/CD) ------------------
    ScenarioCategory(
        id="cicd-poisoned-pipeline-execution",
        domain="cicd_supply_chain",
        name="Poisoned Pipeline Execution",
        summary=(
            "An attacker submits a pull request that triggers a CI job with write access to "
            "secrets, injecting a build step that exfiltrates credentials and backdoors the "
            "resulting artifact."
        ),
        suggested_tactics=("Initial Access", "Execution", "Exfiltration"),
        suggested_techniques=("T1195.002 Compromise Software Supply Chain",),
        primary_log_sources=("linux",),
        source="OWASP Top 10 CI/CD Security Risks CICD-SEC-4",
    ),
    ScenarioCategory(
        id="cicd-dependency-chain-abuse",
        domain="cicd_supply_chain",
        name="Dependency Chain Abuse",
        summary=(
            "A typosquatted or takeover-compromised open-source package is pulled "
            "automatically into a build pipeline, executes arbitrary code on the build "
            "agent, and exfiltrates CI secrets to an external host."
        ),
        suggested_tactics=("Initial Access", "Execution", "Exfiltration"),
        suggested_techniques=("T1195.001 Compromise Software Dependencies and Development Tools",),
        primary_log_sources=("linux",),
        source="OWASP Top 10 CI/CD Security Risks CICD-SEC-3",
    ),
    ScenarioCategory(
        id="cicd-credential-hygiene",
        domain="cicd_supply_chain",
        name="Insufficient Credential Hygiene",
        summary=(
            "A long-lived CI/CD deploy token is accidentally committed to a public repo; an "
            "attacker finds it via automated secret-scanning and uses it to push a "
            "malicious release directly, bypassing code review entirely."
        ),
        suggested_tactics=("Initial Access", "Persistence"),
        suggested_techniques=("T1552.001 Credentials In Files",),
        primary_log_sources=("linux",),
        source="OWASP Top 10 CI/CD Security Risks CICD-SEC-6",
    ),
    ScenarioCategory(
        id="cicd-insecure-system-configuration",
        domain="cicd_supply_chain",
        name="Insecure System Configuration (exposed runner)",
        summary=(
            "A self-hosted CI runner exposed to the internet with default or no "
            "authentication is found via an internet-wide scan and used as an initial "
            "foothold into the internal network."
        ),
        suggested_tactics=("Reconnaissance", "Initial Access"),
        suggested_techniques=("T1595 Active Scanning", "T1190 Exploit Public-Facing Application"),
        primary_log_sources=("linux", "palo_alto"),
        source="OWASP Top 10 CI/CD Security Risks CICD-SEC-7",
    ),
    ScenarioCategory(
        id="cicd-artifact-integrity",
        domain="cicd_supply_chain",
        name="Improper Artifact Integrity Validation",
        summary=(
            "An unsigned release artifact is swapped for a backdoored version between build "
            "and publish; because nothing verifies artifact integrity, the backdoored build "
            "ships to customers before the tampering is noticed (SolarWinds-pattern)."
        ),
        suggested_tactics=("Initial Access", "Persistence"),
        suggested_techniques=("T1195.002 Compromise Software Supply Chain",),
        primary_log_sources=("linux",),
        source="OWASP Top 10 CI/CD Security Risks CICD-SEC-9",
    ),
    # -- AI / LLM applications (OWASP Top 10 for LLM Apps:2025) --------------
    ScenarioCategory(
        id="llm-prompt-injection-excessive-agency",
        domain="ai_llm",
        name="Prompt Injection + Excessive Agency",
        summary=(
            "A customer-support chatbot with excessive tool permissions is prompt-injected "
            "via a crafted support ticket into calling a tool it was authorized for but "
            "should never have used this way, exfiltrating another customer's data through "
            "the legitimate tool call."
        ),
        suggested_tactics=("Initial Access", "Execution", "Exfiltration"),
        suggested_techniques=("T1204 User Execution",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10 for LLM Applications:2025 LLM01/LLM06",
    ),
    ScenarioCategory(
        id="llm-sensitive-information-disclosure",
        domain="ai_llm",
        name="Sensitive Information Disclosure (RAG)",
        summary=(
            "A retrieval-augmented internal assistant leaks confidential documents to an "
            "unauthorized employee via crafted queries that bypass the document store's "
            "intended access scoping."
        ),
        suggested_tactics=("Collection", "Exfiltration"),
        suggested_techniques=("T1213 Data from Information Repositories",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10 for LLM Applications:2025 LLM02",
    ),
    ScenarioCategory(
        id="llm-improper-output-handling",
        domain="ai_llm",
        name="Improper Output Handling",
        summary=(
            "LLM-generated content is rendered unsanitized into an internal admin "
            "dashboard, resulting in a stored script-injection payload that executes "
            "against an analyst's authenticated session."
        ),
        suggested_tactics=("Execution", "Privilege Escalation"),
        suggested_techniques=("T1059 Command and Scripting Interpreter",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10 for LLM Applications:2025 LLM05",
    ),
    ScenarioCategory(
        id="llm-supply-chain-poisoning",
        domain="ai_llm",
        name="Model/Plugin Supply Chain Poisoning",
        summary=(
            "A third-party fine-tuned model or plugin pulled from a public hub contains a "
            "hidden backdoor trigger phrase that exfiltrates data whenever invoked in "
            "production, discovered only after unusual outbound traffic correlates with "
            "specific chat sessions."
        ),
        suggested_tactics=("Resource Development", "Exfiltration"),
        suggested_techniques=("T1195 Supply Chain Compromise",),
        primary_log_sources=("palo_alto", "linux"),
        source="OWASP Top 10 for LLM Applications:2025 LLM03",
    ),
    # -- Mobile (OWASP Mobile Top 10:2024) -----------------------------------
    ScenarioCategory(
        id="mobile-insecure-data-storage",
        domain="mobile",
        name="Insecure Data Storage (BYOD token theft)",
        summary=(
            "A corporate BYOD app stores an authentication token in plaintext local "
            "storage; a lost/stolen device (or a malicious sideloaded app reading shared "
            "storage) lets an attacker lift the token and impersonate the user against "
            "backend APIs."
        ),
        suggested_tactics=("Credential Access", "Initial Access"),
        suggested_techniques=("T1552 Unsecured Credentials",),
        primary_log_sources=("palo_alto", "azure_activity"),
        source="OWASP Mobile Top 10:2024 M9",
    ),
    ScenarioCategory(
        id="mobile-insufficient-binary-protection",
        domain="mobile",
        name="Insufficient Binary Protection",
        summary=(
            "An attacker reverse-engineers a mobile app binary to extract a hardcoded "
            "backend API key, then hits the backend directly, bypassing the app's intended "
            "rate limits and business logic."
        ),
        suggested_tactics=("Discovery", "Initial Access"),
        suggested_techniques=("T1552.001 Credentials In Files",),
        primary_log_sources=("palo_alto",),
        source="OWASP Mobile Top 10:2024 M7",
    ),
    ScenarioCategory(
        id="mobile-insecure-communication",
        domain="mobile",
        name="Insecure Communication (AiTM on public wifi)",
        summary=(
            "A mobile app that fails to pin certificates is intercepted via an "
            "adversary-in-the-middle position on public wifi, letting the attacker harvest "
            "session tokens from modified API traffic."
        ),
        suggested_tactics=("Credential Access", "Collection"),
        suggested_techniques=("T1557 Adversary-in-the-Middle",),
        primary_log_sources=("palo_alto",),
        source="OWASP Mobile Top 10:2024 M5",
    ),
    # -- AWS ------------------------------------------------------------------
    ScenarioCategory(
        id="aws-leaked-iam-key",
        domain="aws",
        name="Leaked IAM Access Key",
        summary=(
            "A long-lived IAM access key committed to a public GitHub repo is found by an "
            "automated credential scanner within minutes and used for account "
            "reconnaissance and lateral access into S3 and EC2."
        ),
        suggested_tactics=("Initial Access", "Discovery", "Collection"),
        suggested_techniques=("T1552.001 Credentials In Files", "T1526 Cloud Service Discovery"),
        primary_log_sources=("aws_cloudtrail", "linux"),
        source="AWS Security Incident Response Guide",
    ),
    ScenarioCategory(
        id="aws-public-s3-exposure",
        domain="aws",
        name="Public S3 Bucket Exposure",
        summary=(
            "A misconfigured public S3 bucket is discovered by an opportunistic scanner "
            "and mass-downloaded before the misconfiguration is caught by a routine audit."
        ),
        suggested_tactics=("Discovery", "Collection", "Exfiltration"),
        suggested_techniques=("T1530 Data from Cloud Storage Object",),
        primary_log_sources=("aws_cloudtrail",),
        source="AWS Security Incident Response Guide",
    ),
    ScenarioCategory(
        id="aws-ssrf-metadata-theft",
        domain="aws",
        name="SSRF to Instance Metadata Credential Theft",
        summary=(
            "An SSRF vulnerability in a public-facing web app is used to reach the EC2 "
            "instance metadata service, stealing the instance's IAM role credentials and "
            "pivoting into the broader AWS account (Capital One-pattern)."
        ),
        suggested_tactics=("Initial Access", "Credential Access", "Lateral Movement"),
        suggested_techniques=("T1190 Exploit Public-Facing Application", "T1552.005 Cloud Instance Metadata API"),
        primary_log_sources=("palo_alto", "aws_cloudtrail"),
        source="AWS Security Incident Response Guide",
    ),
    ScenarioCategory(
        id="aws-cloudtrail-tampering",
        domain="aws",
        name="CloudTrail Tampering (defense evasion)",
        summary=(
            "An attacker with an initial IAM foothold disables or deletes CloudTrail "
            "logging mid-intrusion to cover their tracks before completing a data-theft "
            "operation."
        ),
        suggested_tactics=("Defense Evasion", "Exfiltration"),
        suggested_techniques=("T1562.008 Disable Cloud Logs",),
        primary_log_sources=("aws_cloudtrail",),
        source="AWS Security Incident Response Guide",
    ),
    ScenarioCategory(
        id="aws-ec2-cryptomining",
        domain="aws",
        name="Compromised EC2 Cryptomining",
        summary=(
            "An EC2 instance exposed via weak SSH credentials is compromised and "
            "repurposed for cryptomining, discovered only via an anomalous billing/CPU "
            "utilization alert days later."
        ),
        suggested_tactics=("Initial Access", "Impact"),
        suggested_techniques=("T1110 Brute Force", "T1496 Resource Hijacking"),
        primary_log_sources=("aws_cloudtrail", "linux"),
        source="AWS Security Incident Response Guide",
    ),
    # -- Azure / Entra ID -------------------------------------------------------
    ScenarioCategory(
        id="azure-aitm-token-theft",
        domain="azure",
        name="AiTM Session Token Theft ('pass-the-cookie')",
        summary=(
            "An adversary-in-the-middle phishing kit steals a session token during "
            "authentication, letting the attacker replay it and access mailbox/files "
            "despite the user having satisfied MFA."
        ),
        suggested_tactics=("Credential Access", "Initial Access"),
        suggested_techniques=("T1557 Adversary-in-the-Middle", "T1528 Steal Application Access Token"),
        primary_log_sources=("azure_activity", "outlook_message_trace", "email_eml"),
        source="Microsoft token theft playbook",
    ),
    ScenarioCategory(
        id="azure-malicious-oauth-app",
        domain="azure",
        name="Malicious OAuth App (consent phishing)",
        summary=(
            "Consent-phishing tricks a user into granting a malicious OAuth application "
            "persistent API access to their mailbox and files — access that survives a "
            "password reset, since the attacker never needed the password."
        ),
        suggested_tactics=("Persistence", "Collection"),
        suggested_techniques=("T1528 Steal Application Access Token",),
        primary_log_sources=("azure_activity", "outlook_message_trace"),
        source="Microsoft IR blog: preventing cloud identity compromise",
    ),
    ScenarioCategory(
        id="azure-service-principal-token-theft",
        domain="azure",
        name="Service Principal Token Theft (CI/CD)",
        summary=(
            "A compromised CI/CD pipeline exfiltrates a service principal's access token "
            "via CLI output, using it for lateral movement into Azure resources the "
            "pipeline was never meant to reach interactively."
        ),
        suggested_tactics=("Credential Access", "Lateral Movement"),
        suggested_techniques=("T1528 Steal Application Access Token",),
        primary_log_sources=("azure_activity", "linux"),
        source="Microsoft token theft playbook",
    ),
    ScenarioCategory(
        id="azure-adfs-token-forging",
        domain="azure",
        name="AD FS Token-Signing Certificate Theft",
        summary=(
            "An attacker steals the token-signing certificate from a compromised on-prem "
            "AD FS federation server and forges tokens to impersonate any user in Entra "
            "ID, bypassing Entra-side controls entirely."
        ),
        suggested_tactics=("Credential Access", "Defense Evasion", "Persistence"),
        suggested_techniques=("T1606.002 Forge Web Credentials: SAML Tokens",),
        primary_log_sources=("azure_activity", "windows"),
        source="Microsoft IR blog: preventing cloud identity compromise",
    ),
    # -- Google Cloud Platform --------------------------------------------------
    ScenarioCategory(
        id="gcp-leaked-service-account-key",
        domain="gcp",
        name="Leaked Service Account Key",
        summary=(
            "A service-account JSON key accidentally leaked (e.g. via a public commit) is "
            "used directly against the GCP API for reconnaissance, IAM privilege "
            "escalation, and data exfiltration. (This is the same premise as the bundled "
            "gcp_key_compromise.yaml template — choose this category to generate a fresh "
            "variant with a different org, seed, and specific data targeted.)"
        ),
        suggested_tactics=("Discovery", "Privilege Escalation", "Persistence", "Exfiltration"),
        suggested_techniques=("T1526 Cloud Service Discovery", "T1098.001 Additional Cloud Credentials"),
        primary_log_sources=("gcp_audit", "linux"),
        source="Google Cloud Storage threat model",
    ),
    ScenarioCategory(
        id="gcp-public-storage-bucket",
        domain="gcp",
        name="Public Cloud Storage Bucket Exposure",
        summary=(
            "A misconfigured public Cloud Storage bucket is discovered by an opportunistic "
            "scanner and mass-downloaded before the exposure is caught."
        ),
        suggested_tactics=("Discovery", "Collection", "Exfiltration"),
        suggested_techniques=("T1530 Data from Cloud Storage Object",),
        primary_log_sources=("gcp_audit",),
        source="Google Cloud Storage threat model",
    ),
    ScenarioCategory(
        id="gcp-iam-lateral-movement",
        domain="gcp",
        name="IAM Lateral Movement Across Projects",
        summary=(
            "An overly permissive IAM role grant on a service account lets an attacker who "
            "compromised one GCP project pivot into sibling projects in the same "
            "organization."
        ),
        suggested_tactics=("Lateral Movement", "Privilege Escalation"),
        suggested_techniques=("T1078.004 Cloud Accounts",),
        primary_log_sources=("gcp_audit",),
        source="Google Cloud Storage threat model",
    ),
    ScenarioCategory(
        id="gcp-audit-log-tampering",
        domain="gcp",
        name="Cloud Audit Log Tampering",
        summary=(
            "An attacker disables or alters Cloud Audit Log sinks mid-intrusion to cover "
            "their tracks before completing an exfiltration operation."
        ),
        suggested_tactics=("Defense Evasion", "Exfiltration"),
        suggested_techniques=("T1562.008 Disable Cloud Logs",),
        primary_log_sources=("gcp_audit",),
        source="Google Cloud Storage threat model",
    ),
    # -- Windows Client & Server / Active Directory -----------------------------
    ScenarioCategory(
        id="windows-ad-kerberoasting",
        domain="windows_enterprise",
        name="Active Directory Kerberoasting",
        summary=(
            "An attacker requests Kerberos service tickets for accounts with an SPN set, "
            "cracks the tickets offline, and uses a recovered service account password for "
            "lateral movement across the domain."
        ),
        suggested_tactics=("Credential Access", "Lateral Movement"),
        suggested_techniques=("T1558.003 Kerberoasting",),
        primary_log_sources=("windows",),
        source="CISA/NSA/Five-Eyes joint Active Directory guidance",
    ),
    ScenarioCategory(
        id="windows-lsass-credential-dumping",
        domain="windows_enterprise",
        name="LSASS Credential Dumping",
        summary=(
            "LSASS memory is dumped from a compromised workstation; extracted credentials "
            "are used for pass-the-hash lateral movement across multiple domain-joined "
            "hosts."
        ),
        suggested_tactics=("Credential Access", "Lateral Movement"),
        suggested_techniques=("T1003.001 LSASS Memory",),
        primary_log_sources=("windows",),
        source="SANS FOR508",
    ),
    ScenarioCategory(
        id="windows-ransomware-rdp",
        domain="windows_enterprise",
        name="Ransomware via Compromised RDP",
        summary=(
            "Ransomware is deployed through a compromised RDP/VPN endpoint, followed by "
            "Kerberoasting for lateral movement and domain-wide file encryption "
            "(Akira-pattern kill chain)."
        ),
        suggested_tactics=("Initial Access", "Credential Access", "Lateral Movement", "Impact"),
        suggested_techniques=("T1133 External Remote Services", "T1558.003 Kerberoasting", "T1486 Data Encrypted for Impact"),
        primary_log_sources=("windows", "palo_alto"),
        source="CISA Akira ransomware advisory (AA24-109A)",
    ),
    ScenarioCategory(
        id="windows-dcsync-golden-ticket",
        domain="windows_enterprise",
        name="DCSync + Golden Ticket Persistence",
        summary=(
            "An attacker with domain-admin-adjacent access performs a DCSync attack to "
            "steal the krbtgt hash, then forges a Golden Ticket for long-term, hard-to-"
            "remediate domain persistence."
        ),
        suggested_tactics=("Credential Access", "Persistence"),
        suggested_techniques=("T1003.006 DCSync", "T1558.001 Golden Ticket"),
        primary_log_sources=("windows",),
        source="CISA/NSA/Five-Eyes joint Active Directory guidance",
    ),
    ScenarioCategory(
        id="windows-gpo-abuse",
        domain="windows_enterprise",
        name="Group Policy Object Abuse",
        summary=(
            "A malicious Group Policy Object modification pushes a scheduled task to every "
            "domain-joined machine, used for mass lateral movement and ransomware staging "
            "in a single push."
        ),
        suggested_tactics=("Lateral Movement", "Execution", "Persistence"),
        suggested_techniques=("T1484.001 Group Policy Modification",),
        primary_log_sources=("windows",),
        source="CISA/NSA/Five-Eyes joint Active Directory guidance",
    ),
    # -- Linux / Unix client & server -------------------------------------------
    ScenarioCategory(
        id="linux-ssh-bruteforce-persistence",
        domain="linux_unix",
        name="SSH Brute-Force to Server Compromise",
        summary=(
            "SSH brute-forcing (or a stolen key) against an internet-facing Linux server "
            "succeeds, and the attacker establishes cron/systemd-based persistence for "
            "continued access."
        ),
        suggested_tactics=("Credential Access", "Persistence"),
        suggested_techniques=("T1110 Brute Force", "T1053.003 Cron"),
        primary_log_sources=("linux",),
        source="SANS FOR508",
    ),
    ScenarioCategory(
        id="linux-webshell-injection",
        domain="linux_unix",
        name="Web Shell via Injection",
        summary=(
            "A public-facing Linux web server compromised via an injection vulnerability "
            "has a web shell dropped, used for further internal reconnaissance and "
            "credential harvesting."
        ),
        suggested_tactics=("Initial Access", "Persistence", "Discovery"),
        suggested_techniques=("T1190 Exploit Public-Facing Application", "T1505.003 Web Shell"),
        primary_log_sources=("linux", "palo_alto"),
        source="SANS FOR508",
    ),
    ScenarioCategory(
        id="linux-sudo-privilege-escalation",
        domain="linux_unix",
        name="Sudo/SUID Privilege Escalation",
        summary=(
            "An attacker with limited shell access on a Linux server exploits a "
            "misconfigured sudoers entry or SUID binary to escalate to root, then pivots "
            "to other hosts trusting the now-compromised server."
        ),
        suggested_tactics=("Privilege Escalation", "Lateral Movement"),
        suggested_techniques=("T1548.003 Sudo and Sudo Caching",),
        primary_log_sources=("linux",),
        source="SANS FOR508",
    ),
    # -- macOS --------------------------------------------------------------
    ScenarioCategory(
        id="macos-fake-update-malware",
        domain="macos",
        name="Fake-Update Social Engineering Malware",
        summary=(
            "A user is tricked by a fake browser-update page into installing unsigned "
            "malware, which establishes LaunchAgent persistence and begins beaconing out."
        ),
        suggested_tactics=("Initial Access", "Persistence", "Command and Control"),
        suggested_techniques=("T1204.002 Malicious File", "T1543.001 Launch Agent"),
        primary_log_sources=("linux", "palo_alto"),
        source="SANS FOR518",
        notes="Endpoint telemetry renders via the linux syslog emitter — a Unix-family approximation; ForgeIncident has no native macOS Unified Log emitter yet.",
    ),
    ScenarioCategory(
        id="macos-keychain-credential-theft",
        domain="macos",
        name="Keychain Credential Theft",
        summary=(
            "Malware with local access reads the user's Keychain to harvest saved "
            "credentials, which are then used to access corporate SaaS accounts from a new "
            "device."
        ),
        suggested_tactics=("Credential Access",),
        suggested_techniques=("T1555.001 Keychain",),
        primary_log_sources=("linux", "azure_activity"),
        source="SANS FOR518",
        notes="Endpoint telemetry renders via the linux syslog emitter — a Unix-family approximation.",
    ),
    ScenarioCategory(
        id="macos-tcc-gatekeeper-bypass",
        domain="macos",
        name="TCC/Gatekeeper Bypass",
        summary=(
            "An attacker exploits a TCC or Gatekeeper bypass to access sensitive data "
            "(contacts, screen recording) without the usual user-consent prompt, going "
            "undetected until an EDR behavioral rule flags the anomalous access."
        ),
        suggested_tactics=("Defense Evasion", "Collection"),
        suggested_techniques=("T1548 Abuse Elevation Control Mechanism",),
        primary_log_sources=("linux",),
        source="SANS FOR518",
        notes="Endpoint telemetry renders via the linux syslog emitter — a Unix-family approximation.",
    ),
    # -- Cross-cutting --------------------------------------------------------
    ScenarioCategory(
        id="cross-phishing-lateral-exfil",
        domain="cross_cutting",
        name="Phishing to Lateral Movement to Exfiltration",
        summary=(
            "An employee opens a phishing attachment, malware executes and beacons out, "
            "the attacker moves laterally to a file server, and stages + exfiltrates "
            "sensitive data. (Same premise as the bundled phishing_to_exfil.yaml — choose "
            "this category for a fresh variant with a different org/industry and seed.)"
        ),
        suggested_tactics=("Initial Access", "Execution", "Lateral Movement", "Exfiltration"),
        suggested_techniques=("T1566.001 Spearphishing Attachment", "T1021 Remote Services"),
        primary_log_sources=("email_eml", "outlook_message_trace", "windows", "palo_alto"),
        source="Cross-cutting DFIR staple",
    ),
    ScenarioCategory(
        id="cross-bec-mailbox-rule-fraud",
        domain="cross_cutting",
        name="Business Email Compromise (mailbox rule fraud)",
        summary=(
            "A finance employee's mailbox is compromised (phishing or credential "
            "stuffing); the attacker creates a hidden inbox rule to intercept invoice "
            "threads and redirects a wire payment to a fraudulent account."
        ),
        suggested_tactics=("Initial Access", "Persistence", "Collection", "Impact"),
        suggested_techniques=("T1114.003 Email Forwarding Rule",),
        primary_log_sources=("outlook_message_trace", "email_eml", "azure_activity"),
        source="Cross-cutting DFIR staple",
    ),
    ScenarioCategory(
        id="cross-insider-threat-exfil",
        domain="cross_cutting",
        name="Insider Threat Data Exfiltration",
        summary=(
            "A departing employee mass-downloads confidential files to removable media or "
            "personal cloud storage in the two weeks before their resignation is announced."
        ),
        suggested_tactics=("Collection", "Exfiltration"),
        suggested_techniques=("T1052.001 Exfiltration over USB", "T1567 Exfiltration Over Web Service"),
        primary_log_sources=("windows", "linux"),
        source="Cross-cutting DFIR staple",
    ),
    ScenarioCategory(
        id="cross-removable-media-malware",
        domain="cross_cutting",
        name="Removable Media Malware Introduction",
        summary=(
            "Malware is introduced via a USB drive plugged into a segmented workstation, "
            "establishes persistence, and attempts to bridge back to the broader network."
        ),
        suggested_tactics=("Initial Access", "Persistence", "Command and Control"),
        suggested_techniques=("T1091 Replication Through Removable Media",),
        primary_log_sources=("windows",),
        source="Cross-cutting DFIR staple",
    ),
    ScenarioCategory(
        id="cross-ransomware-end-to-end",
        domain="cross_cutting",
        name="Ransomware: Initial Access to Extortion",
        summary=(
            "A full kill chain from initial access (phishing or exposed RDP) through "
            "staging, domain-wide encryption, and an extortion note, spanning multiple "
            "hosts and log sources."
        ),
        suggested_tactics=("Initial Access", "Lateral Movement", "Impact"),
        suggested_techniques=("T1486 Data Encrypted for Impact",),
        primary_log_sources=("windows", "linux", "palo_alto"),
        source="Cross-cutting DFIR staple",
    ),
)

_CATEGORY_BY_ID = {c.id: c for c in CATEGORIES}


def categories_in_domain(domain_id: str) -> list[ScenarioCategory]:
    get_domain(domain_id)  # validates domain_id, raises KeyError with a helpful message
    return [c for c in CATEGORIES if c.domain == domain_id]


def get_category(category_id: str) -> ScenarioCategory:
    try:
        return _CATEGORY_BY_ID[category_id]
    except KeyError as exc:
        raise KeyError(
            f"Unknown scenario category {category_id!r}. Run `forge-incident categories` "
            "to list all available categories."
        ) from exc


def all_category_ids() -> list[str]:
    return [c.id for c in CATEGORIES]
