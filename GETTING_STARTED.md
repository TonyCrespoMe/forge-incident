# Getting Started with ForgeIncident

A complete, beginner-friendly walkthrough: downloading the project, installing it on Windows/macOS/Linux, generating your first training package, requesting a new scenario in plain English, wiring up an LLM provider's API key, generating a genuinely brand-new scenario from a 56-category taxonomy, and publishing the project to GitHub.

If you want the technical architecture (how the code is organized, the full YAML scenario schema for writing brand-new scenarios from scratch), see [README.md](README.md). This guide is the "just tell me what to type" version.

## Contents

1. [What you need before you start](#1-what-you-need-before-you-start)
2. [Download the project](#2-download-the-project)
3. [Install — pick your OS](#3-install--pick-your-os)
4. [Verify it works](#4-verify-it-works)
5. [Generate your first package](#5-generate-your-first-package)
6. [Request a new scenario in plain English](#6-request-a-new-scenario-in-plain-english)
7. [Add an API key for an LLM provider](#7-add-an-api-key-for-an-llm-provider)
8. [Generate a brand-new scenario (generate-category)](#8-generate-a-brand-new-scenario-generate-category)
9. [Understand what you got: student vs. instructor package](#9-understand-what-you-got-student-vs-instructor-package)
10. [Publish this project to GitHub](#10-publish-this-project-to-github)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. What you need before you start

- **Python 3.10 or newer.** Check with `python3 --version` (macOS/Linux) or `python --version` (Windows). If that's below 3.10 or missing entirely, install from [python.org/downloads](https://www.python.org/downloads/) — on Windows, make sure to tick **"Add python.exe to PATH"** during install.
- **Git** (optional, only if you're downloading via `git clone` or want to publish to GitHub later). Get it from [git-scm.com](https://git-scm.com/downloads) or your OS package manager.
- Nothing else. ForgeIncident works **fully offline** — no API key, no account, no internet connection required for its core purpose (generating training packages from the bundled scenarios).

## 2. Download the project

Pick one:

**Option A — clone with Git** (recommended if you have Git):

```bash
git clone https://github.com/forge-incident/forge-incident.git
cd forge-incident
```

**Option B — download a ZIP** (no Git required): on the GitHub repository page, click the green **Code** button → **Download ZIP**, then unzip it anywhere (e.g. your Desktop or Documents folder) and open a terminal in that unzipped folder.

Either way, you should now be sitting in a folder containing `pyproject.toml`, `README.md`, a `src/` folder, and a `scenarios/` folder.

## 3. Install — pick your OS

All three platforms follow the same four steps — create an isolated Python environment ("virtual environment"), activate it, install the project into it, and confirm it worked. The only difference is the exact commands your shell uses.

### macOS

Open **Terminal** (Applications → Utilities → Terminal, or search Spotlight for "Terminal"), `cd` into the folder from Step 2, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Your prompt should now start with `(.venv)`, meaning the virtual environment is active.

### Windows

Open **PowerShell** (search the Start menu for "PowerShell") or **Command Prompt**, `cd` into the folder from Step 2, then:

**PowerShell:**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

**Command Prompt (cmd.exe):**
```bat
python -m venv .venv
.venv\Scripts\activate.bat
pip install -e ".[dev]"
```

If PowerShell refuses to run the activation script with a message about execution policies, run this once (it only relaxes the policy for your user account) and try activating again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Linux

Open your terminal, `cd` into the folder from Step 2, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

(On Debian/Ubuntu, if `python3 -m venv` fails complaining about `ensurepip`, install it first with `sudo apt install python3-venv`.)

> **Every time you come back to a new terminal window**, you need to re-activate the virtual environment (`source .venv/bin/activate` on macOS/Linux, `.venv\Scripts\Activate.ps1` on Windows) before running `forge-incident` commands. If commands stop being found, this is almost always why — see [Troubleshooting](#10-troubleshooting).

## 4. Verify it works

With the virtual environment active (see above), run:

```bash
forge-incident version
forge-incident list
```

`list` should print a table with two bundled scenarios: `phishing-to-exfil-01` and `gcp-key-compromise-01`, both marked `ok`. If you see that table, everything is installed correctly.

## 5. Generate your first package

```bash
forge-incident generate scenarios/phishing_to_exfil.yaml
```

This writes two ZIP files into an `output/` folder:

- `phishing-to-exfil-01-seed20260310-student.zip` — the "mockup logs" (realistic but entirely synthetic firewall logs, email exports, Windows event logs, etc.) plus a short student briefing. This is what you hand to a trainee.
- `phishing-to-exfil-01-seed20260310-instructor.zip` — the same logs, plus the full annotated kill-chain, the **answer key** (the "new scenario questions" — instructor's question/answer pairs tied to specific log entries), and a machine-readable manifest.

Open either ZIP with your normal file explorer / Archive Utility / `unzip` — there's nothing special about them.

Want the exact same package again later, byte-for-byte? Just re-run the same command — everything is seeded and deterministic. Want a *variation* of the same story with different jitter? Add `--seed 42` (or any number) to get a different-but-still-internally-consistent timeline.

## 6. Request a new scenario in plain English

```bash
forge-incident generate-nl "a phishing email that leads to lateral movement and data exfiltration"
```

This is the natural-language path. **Important, honest caveat:** right now this doesn't fabricate a brand-new attack timeline out of thin air — it reads your prompt, picks whichever of the bundled scenario templates best matches what you described (printing its reasoning as `rationale` so you can see why), and lets you override the difficulty/title. The actual logs, timestamps, and identifiers still come from one of the two vetted, internally-consistent templates in `scenarios/`.

That's a deliberate safety/consistency tradeoff, not a limitation nobody noticed: it's what guarantees every IP, username, and file hash in the package you get stays correlated across every log file, no matter which backend you use. If you want a genuinely new attack story (a different industry, a ransomware chain, a supply-chain compromise, whatever), the way to add one is to write a new YAML scenario file — see the **"Writing your own scenario"** section of [README.md](README.md) for the full field-by-field guide. It's a template you fill in (organization, actors, hosts, a timeline of events with `+Nm`-style offsets), not code.

By default `generate-nl` works fully offline (no API key needed) using simple, transparent keyword matching. To have an actual LLM read your prompt and pick more thoughtfully, see the next section.

Useful flags:

```bash
forge-incident generate-nl "a ransomware-style scenario for absolute beginners" --difficulty beginner
forge-incident generate-nl "cloud credential leak" --llm claude   # needs an API key, see Step 7
forge-incident generate-nl "..." --output ~/Desktop/my-package    # write ZIPs somewhere else
```

## 7. Add an API key for an LLM provider

Every provider below is **optional** — skip this whole section if you're happy with the default offline (`none`) backend from Step 6.

First, copy the example environment file once:

```bash
cp .env.example .env        # macOS/Linux
copy .env.example .env      # Windows (cmd.exe)
Copy-Item .env.example .env # Windows (PowerShell)
```

Then open `.env` in any text editor and fill in the section for whichever provider you want. `.env` is already git-ignored, so your key never gets committed by accident.

| Provider | Get a key at | Install extra | Set in `.env` |
|---|---|---|---|
| **Anthropic Claude** | [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) | `pip install -e ".[claude]"` | `ANTHROPIC_API_KEY`, `FORGE_LLM_BACKEND=claude` |
| **OpenAI (ChatGPT/GPT)** | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | `pip install -e ".[openai]"` | `OPENAI_API_KEY`, `FORGE_LLM_BACKEND=openai` |
| **Google Gemini** | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) | `pip install -e ".[gemini]"` | `GEMINI_API_KEY`, `FORGE_LLM_BACKEND=gemini` |
| **xAI Grok** | [console.x.ai](https://console.x.ai) | `pip install -e ".[grok]"` | `XAI_API_KEY`, `FORGE_LLM_BACKEND=grok` |
| **Ollama** (local, free, no account) | n/a — install [ollama.com](https://ollama.com), then `ollama pull llama3.1` | `pip install -e ".[ollama]"` | `FORGE_LLM_BACKEND=ollama` |

You only need to install the extra for the ONE provider you're using (or `pip install -e ".[all]"` to grab all of them at once). After editing `.env` and installing the extra, either:

```bash
forge-incident generate-nl "your prompt here" --llm claude
```

or set `FORGE_LLM_BACKEND=claude` (or `openai`/`gemini`/`grok`/`ollama`) in `.env` and just run `forge-incident generate-nl "..."` with no `--llm` flag.

Every one of these backends is restricted to the same thing described in Step 6: picking a template and a difficulty/title, never inventing log content directly. So switching providers changes *which template gets chosen and how it's framed*, not the underlying log data's trustworthiness.

If a provider isn't configured correctly, ForgeIncident tells you exactly what's missing rather than a cryptic stack trace, e.g.:

```
The 'claude' backend isn't available (missing dependency, API key, or unreachable).
Try --llm none to generate fully offline, or check your .env against .env.example.
```

## 8. Generate a brand-new scenario (generate-category)

Step 6's `generate-nl` only ever picks among the scenario files already in `scenarios/`. If you want an actually NEW scenario — a fresh org, fresh timeline, a category neither bundled scenario covers (a Windows Kerberoasting attack, an AWS leaked-key incident, a phishing-driven business email compromise, an LLM chatbot prompt-injection scenario, and 50-odd more) — that's `generate-category`. It requires a real LLM backend (set up in Step 7 first — `--llm none` doesn't work here, since inventing a whole new scenario needs actual model creativity, not keyword matching).

First, see what's available:

```bash
forge-incident categories                          # everything, grouped by domain
forge-incident categories --domain windows_enterprise   # just one domain
```

Then generate one:

```bash
forge-incident generate-category --category windows-ad-kerberoasting --difficulty advanced --llm claude
```

What you'll see: the tool tells you which attempt it succeeded on (it automatically retries up to 3 times if the model's first attempt doesn't pass validation), prints any consistency warnings, saves the generated YAML into `scenarios/generated/` (so you can read/edit/reuse it exactly like a hand-written one), and packages it exactly like every other command.

**One thing to know:** the instructor ZIP for a `generate-category` scenario is explicitly marked "⚠ LLM-generated scenario — review before classroom use" at the top of `INSTRUCTOR_GUIDE.md`, along with any automated consistency warnings. Give it the same once-over you'd give any new exercise before assigning it — the validate/retry loop guarantees it's structurally sound (every reference resolves, every ID is well-formed), not that the story is polished on the first try. The student package is completely unaffected by any of this — students never see a difference between a hand-written and an LLM-generated scenario.

For the full list of categories and where they come from (OWASP's various Top 10 lists, MITRE ATT&CK, CISA/cloud-provider incident-response guidance), see [SCENARIO_CATEGORY_TAXONOMY.md](SCENARIO_CATEGORY_TAXONOMY.md).

**This costs real money** (except `--llm ollama`, which runs on your own machine for free) — every `generate-category` call is a billed API request. Expect roughly a fraction of a cent to a couple of cents per scenario on OpenAI/Gemini/Grok, and low-teens-of-cents on Claude, more if the validate/retry loop needs a second attempt. See [COST_ESTIMATES.md](COST_ESTIMATES.md) for the dated, per-backend, per-difficulty breakdown — "dated" because LLM pricing (and which model names still work) changes every few months.

## 9. Understand what you got: student vs. instructor package

| | Student ZIP | Instructor ZIP |
|---|---|---|
| Mockup logs (firewall, email, Windows events, etc.) | ✅ | ✅ (identical bytes) |
| Non-spoiler briefing (`README.md`) | ✅ | ✅ |
| Full narrative + MITRE ATT&CK mapping (`INSTRUCTOR_GUIDE.md`) | ❌ | ✅ |
| Answer key / grading questions (`ANSWER_KEY.md`) | ❌ | ✅ |
| Machine-readable manifest for grading tooling (`manifest.json`) | ❌ | ✅ |
| Original scenario source YAML | ❌ | ✅ |

Hand the student ZIP to trainees. Keep the instructor ZIP for yourself/your grading team — it's the one with the answers.

## 10. Publish this project to GitHub

If you haven't already turned this folder into a Git repository:

```bash
cd forge-incident
git init
git add .
git commit -m "Initial commit: ForgeIncident"
```

(The `.gitignore` already excludes your `.env`, `.venv/`, `output/`, and generated ZIPs, so none of your secrets or generated packages get committed by accident — double check with `git status` before your first commit if you want to be extra sure.)

Then, on [github.com](https://github.com/new), create a new **empty** repository (don't let GitHub add a README/license/`.gitignore` — you already have those). GitHub will show you a remote URL like `https://github.com/YOUR-USERNAME/forge-incident.git`. Back in your terminal:

```bash
git remote add origin https://github.com/YOUR-USERNAME/forge-incident.git
git branch -M main
git push -u origin main
```

You'll be prompted to authenticate — GitHub no longer accepts your account password for this; use a [Personal Access Token](https://github.com/settings/tokens) as the password, or set up the [GitHub CLI](https://cli.github.com/) (`gh auth login`) or an SSH key instead, whichever you're already comfortable with.

## 11. Troubleshooting

**`forge-incident: command not found` (or `'forge-incident' is not recognized...` on Windows)**
Your virtual environment isn't active. Re-run the activation command from Step 3 (you should see `(.venv)` at the start of your prompt), then try again. If it's still missing after activating, re-run `pip install -e ".[dev]"`.

**`python3: command not found` / `python: command not found`**
Python isn't installed, or isn't on your PATH. Reinstall from [python.org](https://www.python.org/downloads/) and, on Windows, make sure "Add python.exe to PATH" is checked.

**PowerShell: "running scripts is disabled on this system"**
Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then retry activating the virtual environment.

**`pip install -e ".[dev]"` fails to build / network errors**
Make sure you're actually online (this step needs to download packages) and that `pip` itself is reasonably current: `python -m pip install --upgrade pip`, then retry.

**A provider backend says "isn't available"**
Almost always one of: the extra isn't installed (`pip install -e ".[claude]"` etc.), the key isn't set in `.env` (and you copied `.env.example` to `.env`, not just edited the example), or — for Ollama — `ollama serve` isn't running. The error message names the specific fix.

**`forge-incident list` shows a scenario as `invalid`**
That's the tool doing its job — it validates every scenario file and tells you exactly which field is wrong. Read the printed error; it names the file and the bad field.

Still stuck? Run `pytest` from the project root (virtual environment active) — if all tests pass, your installation is solid and the issue is specific to whatever command you ran; if tests fail, that failure output is the most useful thing to share when asking for help.
