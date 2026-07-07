use taurishield_core::Manifest;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct FilesystemRule;

impl Rule for FilesystemRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        if manifest.security.permissions.filesystem {
            report.add(Violation {
                id: "TS1002",
                severity: Severity::High,
                category: Category::Permission,
                title: "Filesystem permission is forbidden",
                description: "Filesystem access increases host data exposure risk.",
                fix: "Remove filesystem permission from the manifest.",
                reference: "docs/SECURITY_GUARANTEES.md#4-no-filesystem-permissions",
            });
        }
    }
}
