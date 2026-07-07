use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    Permission,
    Network,
    Csp,
    Allowlist,
    Profile,
    Isolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub id: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub title: &'static str,
    pub description: &'static str,
    pub fix: &'static str,
    pub reference: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationReport {
    pub passed: bool,
    pub score: u8,
    pub violations: Vec<Violation>,
}

impl Default for EvaluationReport {
    fn default() -> Self {
        Self {
            passed: true,
            score: 100,
            violations: Vec::new(),
        }
    }
}

impl EvaluationReport {
    pub fn add(&mut self, violation: Violation) {
        if matches!(violation.severity, Severity::Critical | Severity::High) {
            self.passed = false;
        }

        self.score = self.score.saturating_sub(score_penalty(violation.severity));
        self.violations.push(violation);
    }

    pub fn has_blocking_violations(&self) -> bool {
        !self.passed
    }
}

fn score_penalty(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 40,
        Severity::High => 25,
        Severity::Medium => 10,
        Severity::Low => 5,
        Severity::Info => 0,
    }
}
