use serde::Deserialize;
use std::path::Path;

use crate::findings::Finding;

/// A baseline suppresses known, reviewed findings so a scan of vetted skills can exit
/// clean. Entries match by `rule_id`, optionally narrowed to a specific `skill` and/or
/// `file`. Suppression is applied BEFORE scoring, so a suppressed finding neither shows
/// nor counts toward the risk score.
#[derive(Debug, Default, Deserialize)]
pub struct Baseline {
    #[serde(default, rename = "suppress")]
    entries: Vec<Suppress>,
}

#[derive(Debug, Deserialize)]
struct Suppress {
    rule_id: String,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default)]
    file: Option<String>,
    // Documentation for the human reader of the baseline file; not used by matching.
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

/// Conventional baseline filename auto-loaded from the scan target directory.
pub const DEFAULT_FILENAME: &str = ".skillguardai-baseline.toml";

impl Baseline {
    pub fn from_toml_str(s: &str) -> anyhow::Result<Baseline> {
        Ok(toml::from_str(s)?)
    }

    pub fn load(path: &Path) -> anyhow::Result<Baseline> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("baseline {}: {e}", path.display()))?;
        Baseline::from_toml_str(&s)
    }

    /// True when some entry matches this finding: same `rule_id`, and — where the entry
    /// sets them — the same `skill` name and `file` path.
    pub fn suppresses(&self, skill_name: &str, f: &Finding) -> bool {
        self.entries.iter().any(|e| {
            e.rule_id == f.rule_id
                && e.skill.as_deref().is_none_or(|s| s == skill_name)
                && e.file.as_deref().is_none_or(|ff| ff == f.file)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn finding(rule_id: &str, file: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            category: "c".into(),
            severity: Severity::High,
            description: "d".into(),
            file: file.into(),
            line: Some(1),
            snippet: None,
        }
    }

    #[test]
    fn empty_baseline_suppresses_nothing() {
        let b = Baseline::default();
        assert!(!b.suppresses("any", &finding("exec-eval", "SKILL.md")));
    }

    #[test]
    fn suppresses_by_rule_and_skill() {
        let b = Baseline::from_toml_str(
            "[[suppress]]\nrule_id = \"exfil-curl-pipe-sh\"\nskill = \"rust-sudarshan\"\nreason = \"rustup\"\n",
        )
        .unwrap();
        assert!(b.suppresses("rust-sudarshan", &finding("exfil-curl-pipe-sh", "SKILL.md")));
        // wrong skill -> not suppressed
        assert!(!b.suppresses("other-skill", &finding("exfil-curl-pipe-sh", "SKILL.md")));
        // wrong rule -> not suppressed
        assert!(!b.suppresses("rust-sudarshan", &finding("exec-eval", "SKILL.md")));
    }

    #[test]
    fn skill_unset_matches_any_skill() {
        let b = Baseline::from_toml_str("[[suppress]]\nrule_id = \"exec-eval\"\n").unwrap();
        assert!(b.suppresses("skill-a", &finding("exec-eval", "SKILL.md")));
        assert!(b.suppresses("skill-b", &finding("exec-eval", "other.md")));
    }

    #[test]
    fn file_narrows_the_match() {
        let b = Baseline::from_toml_str(
            "[[suppress]]\nrule_id = \"exec-eval\"\nfile = \"docs/notes.md\"\n",
        )
        .unwrap();
        assert!(b.suppresses("s", &finding("exec-eval", "docs/notes.md")));
        assert!(!b.suppresses("s", &finding("exec-eval", "SKILL.md")));
    }
}
