use taurishield_core::Manifest;

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    if manifest.security.permissions.filesystem {
        violations.push(Violation {
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
