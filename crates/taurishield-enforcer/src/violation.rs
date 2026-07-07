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
    Identity,
    Capability,
    Updater,
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

impl EvaluationReport {
    pub fn has_blocking_violations(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.severity, Severity::Critical | Severity::High))
    }
}
