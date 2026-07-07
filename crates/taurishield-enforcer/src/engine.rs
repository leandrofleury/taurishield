use taurishield_core::Manifest;

use crate::rules;
use crate::score::calculate_score;
use crate::{EvaluationReport, Severity};

pub struct Enforcer;

impl Enforcer {
    pub fn evaluate(manifest: &Manifest) -> EvaluationReport {
        evaluate(manifest)
    }
}

pub fn evaluate(manifest: &Manifest) -> EvaluationReport {
    let mut violations = Vec::new();

    rules::shell::check(manifest, &mut violations);
    rules::filesystem::check(manifest, &mut violations);
    rules::permissions::check(manifest, &mut violations);
    rules::allowlist::check(manifest, &mut violations);
    rules::network::check(manifest, &mut violations);
    rules::csp::check(manifest, &mut violations);
    rules::updater::check(manifest, &mut violations);

    let passed = !violations
        .iter()
        .any(|v| matches!(v.severity, Severity::Critical | Severity::High));

    EvaluationReport {
        passed,
        score: calculate_score(&violations),
        violations,
    }
}
