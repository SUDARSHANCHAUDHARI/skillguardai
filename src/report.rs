use serde::Serialize;
use crate::findings::Finding;
use crate::score::Score;

#[derive(Serialize)]
pub struct SkillReport {
    pub skill: String,
    pub score: Score,
    pub findings: Vec<Finding>,
    pub has_executable_scripts: bool,
}

pub fn to_json(reports: &[SkillReport]) -> String {
    serde_json::to_string_pretty(reports).expect("serialize reports")
}

pub fn print_terminal(reports: &[SkillReport]) {
    for r in reports {
        println!("{}  [{:?} {}]{}", r.skill, r.score.band, r.score.value,
            if r.has_executable_scripts { "  (ships scripts)" } else { "" });
        for f in &r.findings {
            let line = f.line.map(|l| l.to_string()).unwrap_or_else(|| "-".into());
            println!("  {:<8?} {:<18} {}:{}  {}", f.severity, f.category, f.file, line, f.description);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::{Band, Score};
    #[test]
    fn json_contains_skill_and_band() {
        let r = SkillReport {
            skill: "demo".into(),
            score: Score { value: 65, band: Band::High, exit_code: 1 },
            findings: vec![], has_executable_scripts: true,
        };
        let out = to_json(&[r]);
        assert!(out.contains("\"skill\": \"demo\""));
        assert!(out.contains("\"HIGH\""));
    }
}
