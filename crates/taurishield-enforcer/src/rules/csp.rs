use taurishield_core::{CspMode, Manifest, SecurityProfile};

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct CspRule;

impl Rule for CspRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        if matches!(
            manifest.security.profile,
            SecurityProfile::Strict | SecurityProfile::Kiosk
        ) && manifest.security.csp != CspMode::Strict
        {
            report.add(Violation {
                id: "TS4001",
                severity: Severity::High,
                category: Category::Csp,
                title: "Strict profile requires strict CSP",
                description: "Strict and kiosk profiles must enforce strict CSP mode.",
                fix: "Set security.csp to strict.",
                reference: "docs/SECURITY_GUARANTEES.md#2-csp-is-mandatory",
            });
        }
    }
}
