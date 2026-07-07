use crate::Severity;
use crate::Violation;

pub fn calculate_score(violations: &[Violation]) -> u8 {
    let mut score: i32 = 100;

    for violation in violations {
        score -= match violation.severity {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 10,
            Severity::Low => 5,
            Severity::Info => 0,
        };
    }

    score.clamp(0, 100) as u8
}
