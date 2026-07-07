use taurishield_core::Manifest;

use crate::{
    rule::Rule,
    rules::{
        allowlist::AllowlistRule, csp::CspRule, filesystem::FilesystemRule,
        isolation::IsolationRule, network::NetworkRule, permissions::PermissionsRule,
        profile::ProfileRule, shell::ShellRule,
    },
    EvaluationReport,
};

pub struct Enforcer;

impl Enforcer {
    pub fn evaluate(manifest: &Manifest) -> EvaluationReport {
        let mut report = EvaluationReport::default();

        let rules: [&dyn Rule; 8] = [
            &ShellRule,
            &FilesystemRule,
            &PermissionsRule,
            &AllowlistRule,
            &NetworkRule,
            &CspRule,
            &ProfileRule,
            &IsolationRule,
        ];

        for rule in rules {
            rule.evaluate(manifest, &mut report);
        }

        report
    }
}
