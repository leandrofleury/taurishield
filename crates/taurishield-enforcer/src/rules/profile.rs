use taurishield_core::{Manifest, SecurityProfile};

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct ProfileRule;

impl Rule for ProfileRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        if manifest.security.profile == SecurityProfile::Kiosk {
            let permissions = &manifest.security.permissions;
            let has_optional_permissions = permissions.notifications
                || permissions.clipboard
                || permissions.downloads
                || permissions.shell
                || permissions.filesystem
                || permissions.camera
                || permissions.microphone
                || permissions.geolocation;

            if has_optional_permissions {
                report.add(Violation {
                    id: "TS5001",
                    severity: Severity::High,
                    category: Category::Profile,
                    title: "Kiosk profile requires all optional permissions disabled",
                    description: "Kiosk builds must minimize interaction with host capabilities.",
                    fix: "Disable all optional permissions for kiosk profile.",
                    reference: "docs/SECURITY_PROFILES.md",
                });
            }
        }
    }
}
