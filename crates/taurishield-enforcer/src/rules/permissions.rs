use taurishield_core::Manifest;

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    if manifest.security.permissions.camera {
        violations.push(Violation {
            id: "TS1003",
            severity: Severity::High,
            category: Category::Permission,
            title: "Camera permission is forbidden",
            description: "Camera access is not allowed in the default enterprise baseline.",
            fix: "Remove camera permission from the manifest.",
            reference: "docs/SECURITY_GUARANTEES.md",
        });
    }

    if manifest.security.permissions.microphone {
        violations.push(Violation {
            id: "TS1004",
            severity: Severity::High,
            category: Category::Permission,
            title: "Microphone permission is forbidden",
            description: "Microphone access is not allowed in the default enterprise baseline.",
            fix: "Remove microphone permission from the manifest.",
            reference: "docs/SECURITY_GUARANTEES.md",
        });
    }

    if manifest.security.permissions.geolocation {
        violations.push(Violation {
            id: "TS1005",
            severity: Severity::Medium,
            category: Category::Permission,
            title: "Geolocation permission is discouraged",
            description: "Geolocation can expose sensitive user context.",
            fix: "Disable geolocation unless explicitly required by an approved policy pack.",
            reference: "docs/SECURITY_GUARANTEES.md",
        });
    }

    if manifest.security.permissions.downloads {
        violations.push(Violation {
            id: "TS1011",
            severity: Severity::Medium,
            category: Category::Permission,
            title: "Downloads are disabled by default",
            description:
                "Downloads require explicit review because they introduce file-handling risk.",
            fix: "Disable downloads or use a future approved policy profile.",
            reference: "docs/SECURITY_GUARANTEES.md",
        });
    }
}
