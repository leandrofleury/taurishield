use taurishield_core::Manifest;

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    if manifest.security.permissions.shell {
        violations.push(Violation {
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
