# SkillGuardAI — Design Spec (v1)

- **Status:** Approved for implementation planning
- **Date:** 2026-08-31
- **Brand name:** SkillGuardAI
- **Package / crate / command:** `skillguardai`
- **Repo location:** `~/SUDARSHAN_CODE/sudarshan_repos/RustProjects/skillguardai/`
- **License:** Apache-2.0 (matches the ecosystem; SkillGuardAI is an independent clean-room tool, not a fork of NVIDIA/skillspector)

## 1. Purpose

A static security scanner for **AI-agent skills and plugins** — the packaged
`SKILL.md` + script bundles that Claude Code and similar agents install and run.
It answers one question before you trust a skill: **is this safe to install?**

v1 is a **personal hardening tool**: point it at your own `~/.claude/skills`,
`~/.agents/hooks`, or an unvetted third-party plugin and get a per-skill risk
verdict. It **never executes** the skill and **makes no network calls** — pure
local static analysis.

The design is deliberately structured so it can **graduate** into a publishable
CLI later (npm/crates-style distribution, richer analyzers) without a rewrite.

### Non-goals (v1)

- No skill execution, ever.
- No network calls (no CVE lookups, no LLM calls).
- Not a fork or reimplementation of NVIDIA/skillspector; the concept is shared,
  the code is independent.

## 2. Scope

### In scope (v1)

- Scan a single skill directory: `skillguardai scan <path>`.
- Batch scan a folder of skills: `skillguardai scan <dir> --all`.
- Parse `SKILL.md` YAML frontmatter (name, description, triggers).
- Data-driven pattern rules (TOML rule pack) across 7 categories.
- Two structural checks in Rust (trigger breadth, executable-script presence).
- Weighted risk score (0–100), verdict band, and a decision-shaped exit code.
- Terminal output (default) and `--json`.
- Fail-closed handling of oversized / unreadable input.

### Explicitly deferred to v2 (YAGNI now — clean bolt-ons later)

- LLM semantic second stage.
- OSV.dev / CVE lookups.
- SARIF output.
- MCP-server / runtime-guardrail mode.
- Python AST parsing + taint tracking.
- Unicode-confusable / homoglyph detection.
- Baseline suppression files for false positives.

## 3. Architecture

### 3.1 Crate layout

```
skillguardai/
  Cargo.toml
  rules/
    default.toml          # the rule pack — DATA, not code
  src/
    main.rs               # binary entry; delegates to cli
    cli.rs                # arg/command parsing (scan; --all; --json)
    walker.rs             # safe directory walk + size caps (fail-closed)
    skill.rs              # parse SKILL.md frontmatter; locate scripts
    rules.rs              # load + represent the TOML rule pack
    engine.rs             # apply rules + run structural checks -> findings
    findings.rs           # Finding / Severity / Category types
    score.rs              # weighted score -> verdict band -> exit code
    report.rs             # terminal + JSON rendering
  tests/
    fixtures/             # clean + malicious sample skills
```

Each module has one purpose and a narrow interface, so it can be understood and
tested in isolation:

- `walker` — "give me the safe-to-read text files under this dir." Depends on: fs.
- `skill` — "parse this dir into a structured Skill (metadata + script list)."
  Depends on: walker output, a YAML parser.
- `rules` — "load the rule pack into typed Rule structs." Depends on: TOML + regex.
- `engine` — "given a Skill and Rules, produce Findings." Depends on: skill, rules,
  findings. This is the only module that knows both layers.
- `score` — "given Findings, produce a Score + Verdict + exit code." Pure function.
- `report` — "render Findings + Verdict to terminal or JSON." Pure formatting.

### 3.2 Two-layer detection

**Layer 1 — Rule pack (TOML, data).** Regex/substring patterns live in
`rules/default.toml`. Adding a detection = editing TOML, no recompile. Each rule:

```toml
[[rule]]
id          = "exfil-curl-pipe-sh"
category    = "data-exfiltration"
severity    = "critical"
description = "Pipes a downloaded script straight into a shell"
pattern     = 'curl[^\n]*\|\s*(ba)?sh'
```

Fields: `id` (unique, stable), `category` (one of the 7), `severity`
(`critical|high|medium|low`), `description` (human-readable), `pattern` (Rust
regex applied to file text).

**Layer 2 — Structural checks (Rust, because they need parsing not regex):**

- **Trigger breadth:** a frontmatter trigger of `*`, empty, or `.*` (i.e. the
  skill activates on virtually everything) → an `excessive-trigger` finding.
- **Executable script presence:** any `.sh`, `.py`, `.js`, or hook script in the
  bundle sets the score multiplier and adds an informational note.

### 3.3 Seed categories and rules

Seven categories (a focused cut of the broader taxonomy), ~20–25 seed rules total:

| Category            | Example detections                                        |
|---------------------|-----------------------------------------------------------|
| `prompt-injection`  | "ignore previous instructions", role-override phrasing    |
| `data-exfiltration` | `curl ... | sh`, POSTing file contents to a remote URL    |
| `credential-access` | reads of `~/.ssh/id_*`, `.env`, `~/.aws`, keychains       |
| `dangerous-exec`    | `eval`, `exec`, `os.system`, backtick shell-out           |
| `supply-chain`      | `npm install`/`pip install` from a raw URL or git ref     |
| `excessive-trigger` | overly broad activation (structural check feeds this too) |
| `obfuscation`       | large base64/hex blobs, `base64 -d | sh`                  |

The exact rule list is finalized during implementation (TDD: each fixture drives
the rule that catches it).

## 4. Data flow

```
skillguardai scan <dir> [--all] [--json]
        |
        v
   [walker]  enumerate files, enforce caps, skip binaries  --(oversize/unreadable)--> ERROR (exit 2)
        |
        v
   [skill]   parse SKILL.md frontmatter; collect script list
        |
        v
   [engine]  for each text file: apply rule-pack patterns
             + run structural checks (trigger breadth, scripts)
        |
        v  Findings
   [score]   sum weighted severities x script multiplier -> 0..100
             -> verdict band -> exit code
        |
        v
   [report]  terminal (default) or JSON
```

With `--all`, the flow runs once per immediate subdirectory of `<dir>` that
contains a `SKILL.md`, and the report summarizes all of them (worst verdict drives
the process exit code).

## 5. Scoring and verdict

Additive, capped at 100:

| Severity  | Points |
|-----------|--------|
| CRITICAL  | +50    |
| HIGH      | +25    |
| MEDIUM    | +10    |
| LOW       | +5     |

- **Executable-script multiplier:** final subtotal × **1.3** if the skill ships any
  executable script (dangerous code is far riskier when the bundle can run it).
- **Cap:** score is clamped to 100.

**Bands and exit codes:**

| Band     | Score range | Meaning               | Exit code |
|----------|-------------|-----------------------|-----------|
| LOW      | 0–20        | Looks safe            | 0         |
| MEDIUM   | 21–50       | Caution — review      | 0         |
| HIGH     | 51–80       | Do not trust as-is    | 1         |
| CRITICAL | 81–100      | Do not install        | 1         |
| —        | —           | Scan error            | 2         |

Exit codes are decision-shaped so the tool composes into scripts/hooks: `0` = ok
or caution, `1` = untrusted, `2` = error.

## 6. Error handling (fail-closed)

- **Oversized input** (per-file cap and total-bundle cap): stop, emit an error,
  exit `2`. Never treat an un-scannable bundle as safe.
- **Unreadable files / permission errors:** surface as an error finding; do not
  silently skip.
- **Malformed `SKILL.md` frontmatter:** emit a `low`/`medium` warning finding and
  continue scanning the file contents (a broken manifest is itself suspicious).
- **Missing `SKILL.md`:** still scan any scripts present; note the absence.
- **Binary files:** skipped by the walker (not text; out of scope for regex rules).

Concrete caps (final values tunable in `constants`): max single file 1 MiB, max
total bundle 20 MiB, max file count 2,000. These guard against zip-bomb-style
inputs.

## 7. Testing (TDD)

- `tests/fixtures/` holds sample skills: one **clean** skill (expected LOW, exit 0)
  and one **malicious** skill per category (expected HIGH/CRITICAL, exit 1).
- For each fixture: write the fixture + its expected verdict/exit code **first**,
  then implement the rule/check that makes it pass.
- Pure modules (`score`, `report`) get direct unit tests.
- Integration test runs the real binary against the fixtures and asserts exit codes
  and JSON shape.

## 8. Distribution (v1)

- Local install via `cargo install --path .` — no registry publish in v1.
- Standard repo hygiene via the `repo-setup-sudarshan` workflow: `.gitignore`,
  `README.md`, `LICENSE` (Apache-2.0) before first push.
- Git identity auto-enforced by the existing hook (owner `SUDARSHANCHAUDHARI`).

## 9. Graduation path (context, not v1 work)

When/if it earns a public release: add the deferred v2 analyzers, publish to
crates.io under the confirm-before-publish rule, and standardize the README to the
approved format. The v1 module boundaries (rule pack as data, pure score/report,
isolated engine) are chosen so none of that requires a rewrite.

## 10. Open decisions (resolved)

- Language: **Rust** (single binary, no-egress, matches the Rust roadmap).
- Engine shape: **Approach A** — lean Rust core + data-driven TOML rule pack.
- Positioning: **personal-first, static-only, structured to graduate.**
- Name/location: **`skillguardai`** in **`RustProjects/`**.
