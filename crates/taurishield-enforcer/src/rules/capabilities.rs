use taurishield_core::Manifest;

use crate::{
    rule::Rule,
    EvaluationReport,
    Severity,
    Violation,
};

pub struct CapabilitiesRule;

impl Rule for CapabilitiesRule {
    fn evaluate(
        &self,
        manifest: &Manifest,
        report: &mut EvaluationReport,
    ) {
        let count = manifest.capabilities.len();

        if count == 0 {
            report.add(Violation {
                id: "TS6001",
                severity: Severity::Medium,
                title: "No capabilities defined",
                description:
                    "The application does not declare any capabilities.",
                remediation:
                    "Define explicit capabilities following the principle of least privilege.",
                reference:
                    "docs/SECURITY_GUARANTEES.md#capabilities",
            });

            report.score = report.score.saturating_sub(10);
        }

        if count > 10 {
            report.add(Violation {
                id: "TS6002",
                severity: Severity::Medium,
                title: "Too many capabilities",
                description:
                    "A high number of capabilities increases the attack surface.",
                remediation:
                    "Reduce the application capabilities to the minimum required.",
                reference:
                    "docs/SECURITY_GUARANTEES.md#capabilities",
            });

            report.score = report.score.saturating_sub(10);
        }
    }
}