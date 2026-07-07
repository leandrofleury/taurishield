use taurishield_core::{CspMode, Manifest, SecurityProfile};

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    if matches!(
        manifest.security.profile,
        SecurityProfile::Strict | SecurityProfile::Kiosk
    ) && manifest.security.csp != CspMode::Strict
    {
        violations.push(Violation {
            id: "TS1008",
            severity: Severity::High,
            category: Category::Csp,
            title: "Strict profile requires strict CSP",
            description: "Strict and kiosk profiles must enforce a strict Content Security Policy.",
            fix: "Set security.csp to strict.",
            reference: "docs/SECURITY_GUARANTEES.md#2-csp-is-mandatory",
        });
    }
}
