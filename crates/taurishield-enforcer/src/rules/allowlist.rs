use taurishield_core::Manifest;

use crate::{rule::Rule, Category, EvaluationReport, Severity, Violation};

pub struct AllowlistRule;

impl Rule for AllowlistRule {
    fn evaluate(&self, manifest: &Manifest, report: &mut EvaluationReport) {
        if manifest.allowlist.domains.is_empty() {
            report.add(Violation {
                id: "TS2001",
                severity: Severity::High,
                category: Category::Allowlist,
                title: "Allowlist is empty",
                description: "The manifest does not define explicit remote destinations.",
                fix: "Add explicit hostnames to allowlist.domains.",
                reference: "docs/SECURITY_GUARANTEES.md#7-explicit-allowlist",
            });
        }

        for domain in &manifest.allowlist.domains {
            if domain == "*" || domain == "*.*" {
                report.add(Violation {
                    id: "TS2002",
                    severity: Severity::Critical,
                    category: Category::Allowlist,
                    title: "Global wildcard allowlist is forbidden",
                    description: "A global wildcard allows arbitrary remote origins.",
                    fix: "Replace wildcard entries with explicit hostnames.",
                    reference: "docs/SECURITY_GUARANTEES.md#5-no-remote-wildcards",
                });
            } else if domain.contains('*') && !domain.starts_with("*.") {
                report.add(Violation {
                    id: "TS2003",
                    severity: Severity::High,
                    category: Category::Allowlist,
                    title: "Invalid wildcard allowlist entry",
                    description:
                        "Wildcard patterns must not be used except controlled subdomain patterns.",
                    fix: "Use explicit hostnames. Avoid wildcard allowlist entries.",
                    reference: "docs/SECURITY_GUARANTEES.md#5-no-remote-wildcards",
                });
            } else if domain.starts_with("*.") {
                report.add(Violation {
                    id: "TS2004",
                    severity: Severity::Medium,
                    category: Category::Allowlist,
                    title: "Wildcard subdomain requires review",
                    description: "Wildcard subdomains increase the allowed remote-origin surface.",
                    fix: "Prefer explicit hostnames for enterprise builds.",
                    reference: "docs/SECURITY_GUARANTEES.md#5-no-remote-wildcards",
                });
            }

            if domain.contains("://") || domain.contains('/') {
                report.add(Violation {
                    id: "TS2005",
                    severity: Severity::High,
                    category: Category::Allowlist,
                    title: "Allowlist entries must be hostnames only",
                    description: "Allowlist domains must not include URL schemes or paths.",
                    fix: "Use example.com instead of https://example.com/path.",
                    reference: "docs/MANIFEST_SCHEMA.md",
                });
            }
        }
    }
}
