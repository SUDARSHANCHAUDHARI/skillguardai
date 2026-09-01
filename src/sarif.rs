use serde_json::{json, Value};

use crate::findings::Severity;
use crate::report::SkillReport;

/// SARIF severity level for a finding. SARIF has only error/warning/note, so
/// Critical and High both map to `error`.
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Render scan results as SARIF 2.1.0 for CI / GitHub code-scanning ingestion.
/// One run; each finding becomes a result whose location URI is `<skill>/<file>`
/// so findings from a batch (`--all`) stay distinguishable. Unique rules are
/// collected into `tool.driver.rules`.
pub fn to_sarif(reports: &[SkillReport]) -> String {
    let mut rules: Vec<Value> = Vec::new();
    let mut seen_rules: Vec<String> = Vec::new();
    let mut results: Vec<Value> = Vec::new();

    for r in reports {
        for f in &r.findings {
            if !seen_rules.contains(&f.rule_id) {
                seen_rules.push(f.rule_id.clone());
                rules.push(json!({
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": { "text": f.description },
                    "properties": { "category": f.category },
                }));
            }
            let uri = format!("{}/{}", r.skill, f.file);
            let mut physical = json!({ "artifactLocation": { "uri": uri } });
            if let Some(line) = f.line {
                physical["region"] = json!({ "startLine": line });
            }
            results.push(json!({
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": f.description },
                "locations": [ { "physicalLocation": physical } ],
                "properties": { "skill": r.skill, "category": f.category },
            }));
        }
    }

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [ {
            "tool": { "driver": {
                "name": "SkillGuardAI",
                "informationUri": "https://github.com/SUDARSHANCHAUDHARI/skillguardai",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            } },
            "results": results,
        } ],
    });

    serde_json::to_string_pretty(&doc).expect("serialize sarif")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;
    use crate::score::{Band, Score};

    fn report_with(rule: &str, sev: Severity) -> SkillReport {
        SkillReport {
            skill: "demo".into(),
            score: Score { value: 50, band: Band::Medium, exit_code: 0 },
            findings: vec![Finding {
                rule_id: rule.into(),
                category: "dangerous-exec".into(),
                severity: sev,
                description: "d".into(),
                file: "SKILL.md".into(),
                line: Some(7),
                snippet: None,
            }],
            has_executable_scripts: false,
        }
    }

    #[test]
    fn sarif_is_valid_json_with_expected_shape() {
        let out = to_sarif(&[report_with("exec-eval", Severity::High)]);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "SkillGuardAI");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "exec-eval");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "demo/SKILL.md"
        );
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
    }

    #[test]
    fn severity_maps_to_sarif_levels() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
    }

    #[test]
    fn duplicate_rule_ids_appear_once_in_driver_rules() {
        let reports = vec![
            report_with("exec-eval", Severity::High),
            report_with("exec-eval", Severity::High),
        ];
        let v: Value = serde_json::from_str(&to_sarif(&reports)).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
    }
}
