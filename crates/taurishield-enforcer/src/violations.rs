use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    pub reference: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct EvaluationReport {
    pub score: u8,
    pub violations: Vec<Violation>,
}

impl EvaluationReport {
    pub fn passed(&self) -> bool {
        !self.violations.iter().any(|v| {
            matches!(v.severity, Severity::High | Severity::Critical)
        })
    }

    pub fn add(&mut self, violation: Violation) {
        self.violations.push(violation);
    }
}