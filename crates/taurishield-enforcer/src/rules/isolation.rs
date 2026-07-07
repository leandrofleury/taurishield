use taurishield_core::{domain_matches, Manifest};
use url::Url;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct IsolationRule;

impl Rule for IsolationRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        let Ok(source_url) = Url::parse(&manifest.source.url) else {
            return;
        };

        let Some(host) = source_url.host_str() else {
            return;
        };

        if !manifest
            .allowlist
            .domains
            .iter()
            .any(|domain| domain_matches(host, domain))
        {
            report.add(Violation {
                id: "TS6001",
                severity: Severity::High,
                category: Category::Isolation,
                title: "Source host is not allowlisted",
                description: "The source host must be explicitly covered by the allowlist.",
                fix: "Add the source host to allowlist.domains.",
                reference: "docs/SECURITY_GUARANTEES.md#7-explicit-allowlist",
            });
        }
    }
}
