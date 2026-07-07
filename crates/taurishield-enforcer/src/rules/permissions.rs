use taurishield_core::Manifest;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct PermissionsRule;

impl Rule for PermissionsRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        let permissions = &manifest.security.permissions;

        if permissions.camera {
            report.add(Violation {
                id: "TS1003",
                severity: Severity::High,
                category: Category::Permission,
                title: "Camera permission is forbidden",
                description: "Camera access is not allowed in the default security baseline.",
                fix: "Remove camera permission from the manifest.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }

        if permissions.microphone {
            report.add(Violation {
                id: "TS1004",
                severity: Severity::High,
                category: Category::Permission,
                title: "Microphone permission is forbidden",
                description: "Microphone access is not allowed in the default security baseline.",
                fix: "Remove microphone permission from the manifest.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }

        if permissions.geolocation {
            report.add(Violation {
                id: "TS1005",
                severity: Severity::Medium,
                category: Category::Permission,
                title: "Geolocation permission requires review",
                description: "Geolocation can expose sensitive user context.",
                fix: "Disable geolocation unless it is explicitly required and reviewed.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }

        if permissions.downloads {
            report.add(Violation {
                id: "TS1006",
                severity: Severity::Medium,
                category: Category::Permission,
                title: "Downloads are disabled by default",
                description: "Downloads introduce file-handling and social-engineering risk.",
                fix: "Disable downloads or require an approved policy profile.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }

        if permissions.clipboard {
            report.add(Violation {
                id: "TS1007",
                severity: Severity::Medium,
                category: Category::Permission,
                title: "Clipboard permission requires review",
                description: "Clipboard access can expose sensitive data.",
                fix: "Disable clipboard access unless it is explicitly required.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }

        if permissions.notifications {
            report.add(Violation {
                id: "TS1008",
                severity: Severity::Info,
                category: Category::Permission,
                title: "Notifications enabled",
                description:
                    "Notifications are enabled. This is allowed but recorded for auditability.",
                fix: "Keep notifications enabled only when the wrapped application needs them.",
                reference: "docs/SECURITY_GUARANTEES.md",
            });
        }
    }
}
