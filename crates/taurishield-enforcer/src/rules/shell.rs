use taurishield_core::Manifest;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct ShellRule;

impl Rule for ShellRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        if manifest.security.permissions.shell {
            report.add(Violation {
                id: "TS1001",
                severity: Severity::Critical,
                category: Category::Permission,
                title: "Shell permission is forbidden",
                description: "Shell permissions can expose host command execution capabilities.",
                fix: "Remove shell permission from the manifest.",
                reference: "docs/SECURITY_GUARANTEES.md#3-no-shell-permissions",
            });
        }
    }
}
