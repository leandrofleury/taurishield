use taurishield_core::Manifest;

use crate::{
    rule::Rule,
    EvaluationReport,
    Severity,
    Violation,
};

pub struct UpdaterRule;

impl Rule for UpdaterRule {
    fn evaluate(
        &self,
        manifest: &Manifest,
        report: &mut EvaluationReport,
    ) {
        if !manifest.updater.enabled {
            return;
        }

        if !manifest.updater.pubkey.is_some() {
            report.add(Violation {
                id: "TS8001",
                severity: Severity::Critical,
                title: "Updater without public key",
                description:
                    "The updater is enabled but no public key is configured.",
                remediation:
                    "Configure a signing public key for update verification.",
                reference:
                    "docs/SECURITY_GUARANTEES.md#signed-updates",
            });

            report.score = report.score.saturating_sub(40);
        }
    }
}