use serde::Serialize;
use crate::findings::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Band { Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Score { pub value: u32, pub band: Band, pub exit_code: i32 }

pub fn score(findings: &[Finding], has_executable_scripts: bool) -> Score {
    let mut subtotal: f64 = findings.iter().map(|f| f.severity.points() as f64).sum();
    if has_executable_scripts { subtotal *= 1.3; }
    let value = subtotal.round().min(100.0) as u32;
    let band = match value {
        0..=20 => Band::Low,
        21..=50 => Band::Medium,
        51..=80 => Band::High,
        _ => Band::Critical,
    };
    let exit_code = match band { Band::Low | Band::Medium => 0, _ => 1 };
    Score { value, band, exit_code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    fn f(sev: Severity) -> Finding {
        Finding { rule_id: "x".into(), category: "c".into(), severity: sev,
            description: "d".into(), file: "f".into(), line: None, snippet: None }
    }
    #[test]
    fn empty_is_low_exit_zero() {
        let s = score(&[], false);
        assert_eq!(s.value, 0);
        assert_eq!(s.band, Band::Low);
        assert_eq!(s.exit_code, 0);
    }
    #[test]
    fn one_critical_is_high_band_exit_one() {
        let s = score(&[f(Severity::Critical)], false);
        assert_eq!(s.value, 50);        // 50, no multiplier
        assert_eq!(s.band, Band::Medium);
        assert_eq!(s.exit_code, 0);
    }
    #[test]
    fn script_multiplier_pushes_band_up() {
        let s = score(&[f(Severity::Critical)], true); // 50 * 1.3 = 65
        assert_eq!(s.value, 65);
        assert_eq!(s.band, Band::High);
        assert_eq!(s.exit_code, 1);
    }
    #[test]
    fn score_is_clamped_to_100() {
        let many = vec![f(Severity::Critical); 5]; // 250 * 1.3 -> clamp 100
        let s = score(&many, true);
        assert_eq!(s.value, 100);
        assert_eq!(s.band, Band::Critical);
    }
}
