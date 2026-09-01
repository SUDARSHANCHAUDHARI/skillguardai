# SkillGuardAI

[![crates.io](https://img.shields.io/crates/v/skillguardai?logo=rust)](https://crates.io/crates/skillguardai)
[![Downloads](https://img.shields.io/crates/d/skillguardai?logo=rust)](https://crates.io/crates/skillguardai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.82%2B-orange?logo=rust)

> A static, no-network Rust CLI that scans AI-agent skills and plugins for security issues before you install them.

**SkillGuardAI** (installed as the `skillguardai` command) reads a skill/plugin
directory, matches its files against a rule pack plus structural checks, and prints a
per-skill risk verdict with a decision-shaped exit code — suitable as a pre-install
check or a CI gate. It never executes a scanned skill and never makes a network call.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Rule Categories](#rule-categories)
- [Scoring and Exit Codes](#scoring-and-exit-codes)
- [Baseline Suppression](#baseline-suppression)
- [Trust Model](#trust-model)
- [Development](#development)
- [Project Structure](#project-structure)
- [Release Status](#release-status)
- [License](#license)
- [About](#about)

## Overview

A `SKILL.md` is instructions your agent will follow, and a skill bundle can ship
executable scripts. Installing an untrusted one is running untrusted code with your
permissions — but skills are shared and installed far more casually than code is
reviewed.

SkillGuardAI is the preflight check between "install" and "trust". Point it at a
third-party skill, your own `~/.claude/skills`, or a plugin bundle, and it flags the
patterns that matter — data exfiltration, credential access, dangerous execution,
prompt injection, supply-chain and obfuscation tricks, and overly broad triggers —
without ever running the thing it inspects. It is built for anyone who installs or
publishes agent skills and wants a fast, deterministic answer to "is this safe?"

## Features

- Scan a single skill directory, or every skill under a directory with `--all`.
- Output as a terminal report, JSON, or **SARIF 2.1.0** (`--format terminal|json|sarif`) for CI / GitHub code scanning.
- Pattern rules across six categories in an embedded rule pack, plus structural checks.
- **Unicode-confusable & hidden-character detection**: zero-width / bidi ("Trojan Source") characters and Latin↔Cyrillic/Greek homoglyphs.
- **Python dynamic-execution analysis**: distinguishes dangerous sinks fed dynamic input (`eval(user_input)`) from harmless literals, and flags `shell=True` and unsafe deserialization.
- Risk score (0–100) → severity band → decision-shaped process exit code.
- Distinct-rule scoring: a pattern repeated across many lines counts once, not many times.
- Mention-vs-use awareness: matches inside Markdown inline-code spans (and blocklist/allowlist lines) are treated as documentation, while fenced code blocks and real code files stay fully flagged.
- Baseline suppression: acknowledge reviewed, benign findings so a scan of trusted skills exits clean.
- **MCP server mode** (`skillguardai mcp`): expose a `scan_skill` tool over stdio for runtime guardrails.
- Fail-closed limits and binary/media asset skipping, so large demo assets never derail a scan.
- Static and offline by design: no skill is ever executed and no network request is ever made.

## Installation

### From crates.io (recommended)

```bash
cargo install skillguardai
```

### From source

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/skillguardai.git
cd skillguardai
cargo build --release
```

The binary is created at:

```bash
target/release/skillguardai
```

Optional local install from a source checkout:

```bash
cargo install --path .
```

## Usage

```bash
# Scan a single skill directory
skillguardai scan <path>

# Scan every subdirectory of <path> that contains a SKILL.md
skillguardai scan <path> --all

# Choose an output format: terminal (default), json, or sarif
skillguardai scan <path> --format json
skillguardai scan <path> --all --format sarif > results.sarif

# Suppress reviewed, known-benign findings via a baseline file
skillguardai scan <path> --all --baseline .skillguardai-baseline.toml

# Run as an MCP server over stdio (exposes a scan_skill tool)
skillguardai mcp
```

(`--json` is kept as a back-compat alias for `--format json`.)

Example:

```bash
$ skillguardai scan ~/.claude/skills/some-skill
some-skill  [MEDIUM 30]
  HIGH     credential-access  SKILL.md:12  Reads AWS credentials

$ echo $?
0
```

## Rule Categories

Every finding belongs to one of seven categories. Six are pattern rules in the
embedded rule pack (`rules/default.toml`); `excessive-trigger` is a structural check
against `SKILL.md` frontmatter.

| Category            | What it looks for                                                        |
|---------------------|--------------------------------------------------------------------------|
| `data-exfiltration` | Sending local data out (curl-pipe-to-shell, POSTing files, DNS/webhook exfil) |
| `credential-access` | Reading SSH keys, AWS/cloud credentials, `.env` files, browser cookies, `.netrc` |
| `dangerous-exec`    | `eval`/`exec`, shelling out via `subprocess`/`child_process`, encoded PowerShell |
| `prompt-injection`  | "Ignore previous instructions", system-prompt extraction, persona/jailbreak attempts, hidden unicode |
| `supply-chain`      | Installing packages from raw URLs, unpinned git refs, curl-piped installers |
| `obfuscation`       | Long base64/hex blobs, `eval(atob(...))`, malformed `SKILL.md` frontmatter |
| `excessive-trigger` | A skill declaring an overly broad activation trigger (e.g. `"*"`)        |

## Scoring and Exit Codes

Findings are weighted by severity and summed over distinct rules, then multiplied by
1.3 if the skill ships any executable script (`.sh`, `.bash`, `.py`, `.js`, `.ts`,
`.rb`, `.pl`), then clamped to 100:

| Severity  | Points |
|-----------|--------|
| Critical  | 50     |
| High      | 25     |
| Medium    | 10     |
| Low       | 5      |

| Score range  | Band       | Exit code |
|--------------|------------|-----------|
| 0–20         | LOW        | 0         |
| 21–50        | MEDIUM     | 0         |
| 51–80        | HIGH       | 1         |
| 81–100       | CRITICAL   | 1         |
| (scan error) | —          | 2         |

With `--all`, the worst verdict across all scanned skills drives the process exit
code, and a per-skill scan error isolates to that skill (exit ≥ 2) without aborting
the rest of the batch.

## Baseline Suppression

Real, vetted skills often contain patterns that are genuine but benign — a documented
`curl | sh` installer, a review checklist that names `eval()` as a thing to look for. A
**baseline file** records these so a scan of trusted skills exits clean, without
weakening detection for everything else.

```toml
# .skillguardai-baseline.toml
[[suppress]]
rule_id = "exfil-curl-pipe-sh"
skill   = "rust-sudarshan"          # optional: limit to one skill
reason  = "Official rustup installer, reviewed and trusted."

[[suppress]]
rule_id = "exec-eval"
file    = "docs/review-checklist.md" # optional: limit to one file
reason  = "Checklist names eval() as a review target, not a call."
```

A finding is suppressed when `rule_id` matches and — where set — the `skill`
(frontmatter or directory name) and `file` (relative path) match too. Suppression is
applied **before scoring**, so a suppressed finding neither shows nor counts. Pass a
baseline with `--baseline FILE`, or drop a `.skillguardai-baseline.toml` into the
scanned directory to have it auto-loaded. See
[`.skillguardai-baseline.example.toml`](.skillguardai-baseline.example.toml).

Always fill in `reason` — an undocumented suppression is how a real finding later hides
in plain sight.

## Trust Model

- **Static only.** SkillGuardAI never executes, imports, or evaluates any file in the
  scanned directory — it only reads text and matches it against regex rules.
- **No network calls.** The binary makes no outbound requests of any kind; the rule
  pack is embedded at compile time via `include_str!`.
- **Fail-closed limits.** Scans fail with exit code 2 (rather than silently skipping
  content) if a *text* file exceeds 1 MiB, the bundle exceeds 20 MiB total, or the
  directory contains more than 2000 files. Binary/media assets (video, images, fonts,
  archives, compiled objects) are skipped by extension and never count toward these
  limits — they are not text a scanner reads.
- **Mention vs. use.** Inside Markdown/plain-text docs, a match that falls within an
  inline-code span (`` `eval()` ``) is treated as a mention and suppressed — but only
  there. Matches inside fenced code blocks and in real code files (`.py`, `.sh`, …) are
  always kept, because that is where a real payload would live.
- Rule-based detection still has limits: it can miss disguised attacks and flag benign
  content that describes a risky pattern in prose. Treat a HIGH/CRITICAL verdict as a
  prompt for human review, not a guarantee of malice, and record vetted exceptions in a
  baseline file.

## Development

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

Run these checks locally before publishing changes.

## Project Structure

```text
src/
  main.rs        Binary entry point
  cli.rs         Command-line interface and scan orchestration
  findings.rs    Finding and Severity types
  score.rs       Scoring: findings -> band -> exit code
  rules.rs       Embedded TOML rule-pack loader
  skill.rs       SKILL.md frontmatter parsing and script detection
  walker.rs      Safe file walk with fail-closed size caps
  engine.rs      Rule matching plus structural checks (unicode, triggers)
  taint.rs       Python dynamic-execution analyzer
  baseline.rs    Baseline suppression of reviewed findings
  report.rs      Terminal and JSON rendering
  sarif.rs       SARIF 2.1.0 rendering
  mcp.rs         MCP server (stdio JSON-RPC) exposing scan_skill
rules/
  default.toml   The embedded rule pack (data, not code)
tests/
  cli.rs         End-to-end integration tests
  fixtures/      Clean and malicious sample skills
```

## Release Status

Published on [crates.io](https://crates.io/crates/skillguardai): **`v0.1.0`**.
**`v0.2.0`** is prepared on `main` — SARIF output, unicode-confusable and
hidden-character detection, the Python dynamic-execution analyzer, MCP server mode,
and false-positive tuning — pending publish.

Each release is verified with Clippy, the full test suite, and an optimized release
build before publishing.

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

## About

I'm Sudarshan Chaudhari, a Senior Quality Engineer, Test Automation specialist, and AI systems builder based in Bangkok, Thailand.

I have 13+ years of experience in software quality engineering, working across SaaS, fintech, gaming, web, mobile, cloud, and digital signage platforms. My background combines hands-on test automation with QA leadership, test strategy, CI/CD, release quality, production investigation, and cross-platform validation.

Alongside my professional QA career, I run [SudarshanTechLabs](https://sudarshantechlabs.com/), my independent engineering and product lab where I design, build, test, and ship software across Android, web, AI, cybersecurity, developer tooling, and cross-platform applications.

### What I work on

- ⚙️ **Quality Engineering & Test Automation** — Playwright, Selenium, Cypress, Appium, API testing, automation frameworks, end-to-end testing, CI/CD, release gates, GitHub Actions, risk-based testing, and production validation
- 🤖 **AI Systems & Automation** — AI agents, multi-agent orchestration, MCP servers, AI-assisted QA, prompt tooling, developer workflows, automation systems, and Claude Code plugins
- 📱 **Mobile & Cross-Platform Applications** — Android applications built with Kotlin and Jetpack Compose, Google Play releases, automated build and publishing pipelines, and cross-platform development spanning iOS, web, Windows, and macOS
- 🌐 **Web Applications & Platforms** — Full-stack applications using Next.js, TypeScript, Firebase, Cloudflare, REST APIs, and modern web infrastructure
- 🛠️ **Developer Tooling & CLI Engineering** — Rust, Python, TypeScript, CLI utilities, multi-repository tooling, build automation, release tooling, and engineering productivity systems
- 🛡️ **Cybersecurity & Observability** — Threat detection, log analysis, security auditing, vulnerability assessment, monitoring, and security-focused developer tools
- 📺 **Digital Signage & Device Platforms** — Content validation, playback testing, device compatibility, production investigation, monitoring, and QA across diverse hardware and operating-system environments

My work sits at the intersection of quality engineering, automation, AI, and software development. I approach products with a QA mindset from the beginning: understanding failure modes, designing for testability, automating repetitive work, and building release confidence into the engineering process.

Through SudarshanTechLabs, I also build products and tools from idea to production, covering architecture, development, testing, CI/CD, release automation, monitoring, and ongoing maintenance.

🌐 [sudarshantechlabs.com](https://sudarshantechlabs.com/) · 💼 [LinkedIn](https://linkedin.com/in/sudarshan-chaudhari) · 🐙 [GitHub](https://github.com/SUDARSHANCHAUDHARI) · ✉️ [sunny.sudarshan@gmail.com](mailto:sunny.sudarshan@gmail.com)
