use taurishield_core::Manifest;
use url::Url;

use crate::{Category, Severity, Violation};

pub fn check(manifest: &Manifest, violations: &mut Vec<Violation>) {
    if let Ok(url) = Url::parse(&manifest.source.url) {
        if url.scheme() != "https" {
            violations.push(Violation {
                id: "TS1007",
                severity: Severity::Critical,
                category: Category::Network,
                title: "Remote source must use HTTPS",
                description: "Non-HTTPS remote sources expose users to network interception and content tampering.",
                fix: "Use an HTTPS source URL.",
                reference: "docs/SECURITY_GUARANTEES.md#6-https-required",
            });
        }

        if let Some(host) = url.host_str() {
            if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                violations.push(Violation {
                    id: "TS1010",
                    severity: Severity::Medium,
                    category: Category::Network,
                    title: "Localhost source requires review",
                    description: "Localhost sources are useful in development but risky for production builds.",
                    fix: "Use a production HTTPS origin for release builds.",
                    reference: "docs/SECURITY_GUARANTEES.md",
                });
            }
        }
    }
}
