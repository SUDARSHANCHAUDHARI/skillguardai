//! Lightweight Python dynamic-execution analyzer.
//!
//! This is NOT a full AST dataflow taint engine (that would need a Python-grammar
//! dependency and is disproportionate for a static skill scanner). It captures the
//! high-value part of taint analysis with line-scoped patterns applied ONLY to `.py`
//! files: it distinguishes a dangerous sink fed a *dynamic* argument (a variable,
//! f-string, or concatenation) from one fed a harmless string literal, and flags
//! unsafe deserialization and `shell=True`.

use std::sync::LazyLock;

use crate::findings::{Finding, Severity};

struct TaintRule {
    id: &'static str,
    severity: Severity,
    description: &'static str,
    re: regex::Regex,
}

static RULES: LazyLock<Vec<TaintRule>> = LazyLock::new(|| {
    let r = |p: &str| regex::Regex::new(p).expect("taint regex");
    vec![
        TaintRule {
            id: "taint-eval-dynamic",
            severity: Severity::High,
            description: "eval()/exec() called on a non-literal (dynamic) argument",
            // `(` then optional spaces then a char that is NOT a quote/close-paren:
            // eval("x") is skipped; eval(user_input) / eval(f"...") match.
            re: r(r#"\b(eval|exec)\s*\(\s*[^\s'")]"#),
        },
        TaintRule {
            id: "taint-os-system-dynamic",
            severity: Severity::High,
            description: "os.system() called on a non-literal (dynamic) argument",
            re: r(r#"os\.system\s*\(\s*[^\s'")]"#),
        },
        TaintRule {
            id: "taint-subprocess-shell",
            severity: Severity::High,
            description: "subprocess call with shell=True (command-injection risk)",
            re: r(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
        },
        TaintRule {
            id: "taint-unsafe-deser",
            severity: Severity::High,
            description: "Unsafe deserialization (pickle/marshal/yaml.load)",
            re: r(r"(pickle\.loads|marshal\.loads|yaml\.load)\s*\("),
        },
    ]
});

/// Analyze one Python file. Returns findings (empty for non-`.py` paths). The regex
/// crate has no lookaround, so the `yaml.load` false positive on `SafeLoader` is
/// filtered here in code rather than in the pattern.
pub fn analyze_python(rel: &str, content: &str) -> Vec<Finding> {
    if !rel.to_ascii_lowercase().ends_with(".py") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for rule in RULES.iter() {
            if !rule.re.is_match(line) {
                continue;
            }
            // A yaml.load with an explicit SafeLoader is safe.
            if rule.id == "taint-unsafe-deser"
                && line.contains("yaml.load")
                && line.contains("SafeLoader")
            {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id.into(),
                category: "dangerous-exec".into(),
                severity: rule.severity,
                description: rule.description.into(),
                file: rel.into(),
                line: Some(idx + 1),
                snippet: Some(line.trim().chars().take(160).collect()),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| f.rule_id.clone()).collect()
    }

    #[test]
    fn dynamic_eval_is_flagged_literal_is_not() {
        let dyn_hit = analyze_python("x.py", "result = eval(user_input)\n");
        assert!(ids(&dyn_hit).contains(&"taint-eval-dynamic".to_string()));
        let literal = analyze_python("x.py", "result = eval(\"1 + 1\")\n");
        assert!(!ids(&literal).contains(&"taint-eval-dynamic".to_string()));
    }

    #[test]
    fn subprocess_shell_true_flagged() {
        let hits = analyze_python("run.py", "subprocess.Popen(cmd, shell=True)\n");
        assert!(ids(&hits).contains(&"taint-subprocess-shell".to_string()));
    }

    #[test]
    fn unsafe_deser_flagged_safe_yaml_is_not() {
        let unsafe_hits = analyze_python("a.py", "data = pickle.loads(blob)\n");
        assert!(ids(&unsafe_hits).contains(&"taint-unsafe-deser".to_string()));
        let safe = analyze_python("b.py", "cfg = yaml.load(f, Loader=yaml.SafeLoader)\n");
        assert!(!ids(&safe).contains(&"taint-unsafe-deser".to_string()));
    }

    #[test]
    fn non_python_file_is_ignored() {
        let hits = analyze_python("README.md", "eval(user_input)\n");
        assert!(hits.is_empty());
    }
}
