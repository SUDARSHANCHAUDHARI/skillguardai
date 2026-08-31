# SkillGuardAI

SkillGuardAI is a static, no-network Rust CLI that scans AI-agent skill/plugin
directories for security issues and prints a per-skill risk verdict with a
decision-shaped exit code, suitable for use as a pre-install check or a CI
gate. It never executes a scanned skill and never makes a network call — every
finding comes from reading and pattern-matching text files on disk.

## Install

```bash
cargo install --path .
```

This builds and installs the `skillguardai` binary from this repository (no
crates.io publication in v1).

## Usage

```bash
# Scan a single skill directory
skillguardai scan <path>

# Scan every subdirectory of <path> that contains a SKILL.md
skillguardai scan <path> --all

# Emit machine-readable JSON instead of the terminal report
skillguardai scan <path> --json

# Suppress reviewed, known-benign findings via a baseline file
skillguardai scan <path> --all --baseline .skillguardai-baseline.toml
```

Example:

```bash
$ skillguardai scan ~/.claude/skills/some-skill
some-skill  [MEDIUM 30]
  HIGH     credential-access  SKILL.md:12  Reads AWS credentials

$ echo $?
0
```

## Rule categories

Every finding belongs to one of seven categories. Six are pattern rules in
the embedded rule pack (`rules/default.toml`); `excessive-trigger` is a
structural check against `SKILL.md` frontmatter.

| Category             | What it looks for                                                        |
|-----------------------|---------------------------------------------------------------------------|
| `data-exfiltration`   | Sending local data out (curl-pipe-to-shell, POSTing files, DNS/webhook exfil) |
| `credential-access`   | Reading SSH keys, AWS/cloud credentials, `.env` files, browser cookies, `.netrc` |
| `dangerous-exec`      | `eval`/`exec`, shelling out via `subprocess`/`child_process`, encoded PowerShell |
| `prompt-injection`    | "Ignore previous instructions", system-prompt extraction, persona/jailbreak attempts, hidden unicode |
| `supply-chain`        | Installing packages from raw URLs, unpinned git refs, curl-piped installers |
| `obfuscation`         | Long base64/hex blobs, `eval(atob(...))`, malformed `SKILL.md` frontmatter |
| `excessive-trigger`   | A skill declaring an overly broad activation trigger (e.g. `"*"`)        |

## Scoring and exit codes

Findings are weighted by severity and summed, then multiplied by 1.3 if the
skill ships any executable script (`.sh`, `.bash`, `.py`, `.js`, `.ts`, `.rb`,
`.pl`), then clamped to 100:

| Severity  | Points |
|-----------|--------|
| Critical  | 50     |
| High      | 25     |
| Medium    | 10     |
| Low       | 5      |

| Score range | Band       | Exit code |
|-------------|------------|-----------|
| 0–20        | LOW        | 0         |
| 21–50       | MEDIUM     | 0         |
| 51–80       | HIGH       | 1         |
| 81–100      | CRITICAL   | 1         |
| (scan error) | —         | 2         |

With `--all`, the worst verdict across all scanned skills drives the process
exit code.

## Baseline suppression

Real, vetted skills often contain patterns that are genuine but benign — a
documented `curl | sh` installer, a review checklist that names `eval()` as a
thing to look for. A **baseline file** records these so a scan of trusted skills
exits clean, without weakening detection for everything else.

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
(frontmatter or directory name) and `file` (relative path) match too.
Suppression is applied **before scoring**, so a suppressed finding neither shows
nor counts. Pass a baseline with `--baseline FILE`, or drop a
`.skillguardai-baseline.toml` into the scanned directory to have it auto-loaded.
See [`.skillguardai-baseline.example.toml`](.skillguardai-baseline.example.toml).

Always fill in `reason` — an undocumented suppression is how a real finding
later hides in plain sight.

## Trust model

- **Static only.** SkillGuardAI never executes, imports, or evaluates any
  file in the scanned directory — it only reads text and matches it against
  regex rules.
- **No network calls.** The binary makes no outbound requests of any kind;
  the rule pack is embedded at compile time via `include_str!`.
- **Fail-closed limits.** Scans fail with exit code 2 (rather than silently
  skipping content) if a *text* file exceeds 1 MiB, the bundle exceeds 20 MiB
  total, or the directory contains more than 2000 files. Binary/media assets
  (video, images, fonts, archives, compiled objects) are skipped by extension
  and never count toward these limits — they are not text a scanner reads.
- **Mention vs. use.** Inside Markdown/plain-text docs, a match that falls
  within an inline-code span (`` `eval()` ``) is treated as a mention and
  suppressed — but only there. Matches inside fenced ``` code blocks and in
  real code files (`.py`, `.sh`, …) are always kept, because that is where a
  real payload would live.
- Rule-based detection still has limits: it can miss disguised attacks and
  flag benign content that describes a risky pattern in prose. Treat a
  HIGH/CRITICAL verdict as a prompt for human review, not a guarantee of
  malice, and record vetted exceptions in a baseline file.

## Development

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
```
