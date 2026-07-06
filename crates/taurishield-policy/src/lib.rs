use serde::Serialize;
use taurishield_core::{CspMode, Manifest, SecurityProfile};

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub fn evaluate_manifest(manifest: &Manifest) -> Vec<Finding> {
    let mut findings = Vec::new();

    if manifest.security.permissions.shell {
        findings.push(Finding {
            severity: Severity::Critical,
            code: "TS-PERM-SHELL",
            message: "Shell permission is enabled. TauriShield blocks shell access in the default enterprise baseline.".to_string(),
        });
    }

    if manifest.security.permissions.filesystem {
        findings.push(Finding {
            severity: Severity::High,
            code: "TS-PERM-FS",
            message: "Filesystem permission is enabled. This must be justified by an explicit threat model and custom policy.".to_string(),
        });
    }

    if manifest.security.permissions.camera || manifest.security.permissions.microphone || manifest.security.permissions.geolocation {
        findings.push(Finding {
            severity: Severity::High,
            code: "TS-PERM-SENSITIVE-DEVICE",
            message: "Camera, microphone, or geolocation is enabled. Sensitive device permissions are blocked in v0.3 beta.".to_string(),
        });
    }

    if manifest.security.permissions.clipboard {
        findings.push(Finding {
            severity: Severity::Medium,
            code: "TS-PERM-CLIPBOARD",
            message: "Clipboard permission is enabled. Validate data exfiltration risks.".to_string(),
        });
    }

    if manifest.security.permissions.downloads {
        findings.push(Finding {
            severity: Severity::Medium,
            code: "TS-PERM-DOWNLOADS",
            message: "Downloads are enabled. Validate file handling and user confirmation flows.".to_string(),
        });
    }


    if manifest.security.profile == SecurityProfile::Kiosk {
        if manifest.security.csp != CspMode::Strict {
            findings.push(Finding {
                severity: Severity::High,
                code: "TS-KIOSK-CSP",
                message: "Kiosk profile requires strict CSP mode.".to_string(),
            });
        }
        if manifest.security.permissions.notifications
            || manifest.security.permissions.clipboard
            || manifest.security.permissions.downloads
            || manifest.security.permissions.shell
            || manifest.security.permissions.filesystem
            || manifest.security.permissions.camera
            || manifest.security.permissions.microphone
            || manifest.security.permissions.geolocation
        {
            findings.push(Finding {
                severity: Severity::High,
                code: "TS-KIOSK-PERMISSIONS",
                message: "Kiosk profile requires all optional permissions to be disabled.".to_string(),
            });
        }
    }

    if manifest.security.profile == SecurityProfile::Strict && manifest.security.csp != CspMode::Strict {
        findings.push(Finding {
            severity: Severity::High,
            code: "TS-CSP-STRICT",
            message: "Strict profile requires strict CSP mode.".to_string(),
        });
    }

    for domain in &manifest.allowlist.domains {
        if domain == "*" || domain == "*.*" {
            findings.push(Finding {
                severity: Severity::Critical,
                code: "TS-ALLOWLIST-ANY",
                message: "Global wildcard domain is not allowed.".to_string(),
            });
        } else if domain.contains('*') && !domain.starts_with("*.") {
            findings.push(Finding {
                severity: Severity::High,
                code: "TS-ALLOWLIST-WILDCARD-INVALID",
                message: format!("Invalid wildcard domain pattern detected: {domain}"),
            });
        } else if domain.starts_with("*.") {
            findings.push(Finding {
                severity: Severity::Medium,
                code: "TS-ALLOWLIST-WILDCARD",
                message: format!("Wildcard subdomain detected: {domain}. Prefer explicit hostnames for enterprise builds."),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use taurishield_core::{Allowlist, Application, CspMode, Permissions, Security, Source};

    fn manifest_with_permissions(permissions: Permissions) -> Manifest {
        Manifest {
            application: Application {
                name: "Test".to_string(),
                identifier: "br.com.taurishield.test".to_string(),
                version: "0.3.0-beta.1".to_string(),
            },
            source: Source { url: "https://example.com".to_string() },
            security: Security {
                profile: SecurityProfile::Strict,
                csp: CspMode::Strict,
                permissions,
            },
            allowlist: Allowlist { domains: vec!["example.com".to_string()] },
        }
    }

    #[test]
    fn shell_is_critical() {
        let findings = evaluate_manifest(&manifest_with_permissions(Permissions { shell: true, ..Default::default() }));
        assert!(findings.iter().any(|f| f.code == "TS-PERM-SHELL" && f.severity == Severity::Critical));
    }

    #[test]
    fn filesystem_is_high() {
        let findings = evaluate_manifest(&manifest_with_permissions(Permissions { filesystem: true, ..Default::default() }));
        assert!(findings.iter().any(|f| f.code == "TS-PERM-FS" && f.severity == Severity::High));
    }

    #[test]
    fn strict_profile_requires_strict_csp() {
        let mut manifest = manifest_with_permissions(Permissions::default());
        manifest.security.csp = CspMode::Standard;
        let findings = evaluate_manifest(&manifest);
        assert!(findings.iter().any(|f| f.code == "TS-CSP-STRICT"));
    }

    #[test]
    fn kiosk_blocks_optional_permissions() {
        let mut manifest = manifest_with_permissions(Permissions { notifications: true, ..Default::default() });
        manifest.security.profile = SecurityProfile::Kiosk;
        let findings = evaluate_manifest(&manifest);
        assert!(findings.iter().any(|f| f.code == "TS-KIOSK-PERMISSIONS"));
    }

    #[test]
    fn global_wildcard_is_critical() {
        let mut manifest = manifest_with_permissions(Permissions::default());
        manifest.allowlist.domains = vec!["*".to_string()];
        let findings = evaluate_manifest(&manifest);
        assert!(findings.iter().any(|f| f.code == "TS-ALLOWLIST-ANY" && f.severity == Severity::Critical));
    }
}
