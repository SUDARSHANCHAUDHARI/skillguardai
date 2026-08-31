# SkillGuardAI

SkillGuardAI is a static, no-network Rust CLI that scans AI-agent skill/plugin
directories for security issues (data exfiltration, credential access,
dangerous exec, prompt injection, supply-chain risk, obfuscation, and
excessive triggers) and prints a per-skill risk verdict with a decision-shaped
exit code. It never executes a scanned skill and never makes a network call.

## Usage

```bash
skillguardai scan <path>
```
