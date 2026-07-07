use taurishield_core::Manifest;

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    for domain in &manifest.allowlist.domains {
        if domain == "*" || domain.contains('*') {
            violations.push(Violation {
                id: "TS1006",
                severity: Severity::High,
                category: Category::Allowlist,
                title: "Wildcard allowlist entry is forbidden",
                description: "Wildcard allowlists weaken origin isolation and can allow unintended remote content.",
                fix: "Replace wildcard entries with explicit hostnames.",
                reference: "docs/SECURITY_GUARANTEES.md#5-no-remote-wildcards",
            });
        }

        if domain.starts_with("http://") || domain.starts_with("https://") {
            violations.push(Violation {
                id: "TS1012",
                severity: Severity::High,
                category: Category::Allowlist,
                title: "Allowlist domains must not include URL schemes",
                description: "Allowlist entries must be hostnames only.",
                fix: "Use example.com instead of https://example.com.",
                reference: "docs/MANIFEST_SCHEMA.md",
            });
        }
    }
}
