use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Critical, High, Medium, Low }

impl Severity {
    pub fn points(self) -> u32 {
        match self {
            Severity::Critical => 50,
            Severity::High => 25,
            Severity::Medium => 10,
            Severity::Low => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub description: String,
    pub file: String,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn severity_points_are_correct() {
        assert_eq!(Severity::Critical.points(), 50);
        assert_eq!(Severity::High.points(), 25);
        assert_eq!(Severity::Medium.points(), 10);
        assert_eq!(Severity::Low.points(), 5);
    }
}
