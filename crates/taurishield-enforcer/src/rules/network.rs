use taurishield_core::Manifest;
use url::Url;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct NetworkRule;

impl Rule for NetworkRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        match Url::parse(&manifest.source.url) {
            Ok(url) => {
                if url.scheme() != "https" {
                    report.add(Violation {
                        id: "TS3001",
                        severity: Severity::Critical,
                        category: Category::Network,
                        title: "Source URL must use HTTPS",
                        description:
                            "Non-HTTPS remote sources can be intercepted or modified in transit.",
                        fix: "Use an HTTPS source URL.",
                        reference: "docs/SECURITY_GUARANTEES.md#6-https-required",
                    });
                }

                if let Some(host) = url.host_str() {
                    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                        report.add(Violation {
                            id: "TS3002",
                            severity: Severity::Medium,
                            category: Category::Network,
                            title: "Localhost source requires review",
                            description: "Localhost sources are useful for development but unsafe for production builds.",
                            fix: "Use a production HTTPS origin for distributable builds.",
                            reference: "docs/SECURITY_GUARANTEES.md",
                        });
                    }
                }

                if let Some(port) = url.port() {
                    if port != 443 {
                        report.add(Violation {
                            id: "TS3003",
                            severity: Severity::Low,
                            category: Category::Network,
                            title: "Non-standard HTTPS port",
                            description:
                                "A non-standard source port may require additional review.",
                            fix:
                                "Use HTTPS on TCP/443 unless another port is explicitly justified.",
                            reference: "docs/SECURITY_GUARANTEES.md",
                        });
                    }
                }
            }
            Err(_) => report.add(Violation {
                id: "TS3004",
                severity: Severity::Critical,
                category: Category::Network,
                title: "Invalid source URL",
                description: "The source URL could not be parsed.",
                fix: "Use a valid HTTPS URL.",
                reference: "docs/MANIFEST_SCHEMA.md",
            }),
        }
    }
}
