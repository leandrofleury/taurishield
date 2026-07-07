mod engine;
mod rules;
mod score;
mod violation;

pub use engine::{evaluate, Enforcer};
pub use violation::*;

#[cfg(test)]
mod tests {
    use super::*;
    use taurishield_core::{
        Allowlist, Application, CspMode, Manifest, Permissions, Security, SecurityProfile, Source,
    };

    fn base_manifest() -> Manifest {
        Manifest {
            application: Application {
                name: "Test".to_string(),
                identifier: "br.com.taurishield.test".to_string(),
                version: "1.0.0-rc.1".to_string(),
            },
            source: Source {
                url: "https://example.com".to_string(),
            },
            security: Security {
                profile: SecurityProfile::Strict,
                csp: CspMode::Strict,
                permissions: Permissions::default(),
            },
            allowlist: Allowlist {
                domains: vec!["example.com".to_string()],
            },
        }
    }

    #[test]
    fn secure_manifest_passes() {
        let report = Enforcer::evaluate(&base_manifest());

        assert!(report.passed);
        assert_eq!(report.score, 100);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn shell_permission_fails_with_ts1001() {
        let mut manifest = base_manifest();
        manifest.security.permissions.shell = true;

        let report = Enforcer::evaluate(&manifest);

        assert!(!report.passed);
        assert_eq!(report.violations[0].id, "TS1001");
        assert_eq!(report.violations[0].severity, Severity::Critical);
    }

    #[test]
    fn filesystem_permission_fails_with_ts1002() {
        let mut manifest = base_manifest();
        manifest.security.permissions.filesystem = true;

        let report = Enforcer::evaluate(&manifest);

        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.id == "TS1002"));
    }

    #[test]
    fn wildcard_allowlist_fails_with_ts1006() {
        let mut manifest = base_manifest();
        manifest.allowlist.domains = vec!["*".to_string()];

        let report = Enforcer::evaluate(&manifest);

        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.id == "TS1006"));
    }

    #[test]
    fn strict_profile_requires_strict_csp() {
        let mut manifest = base_manifest();
        manifest.security.csp = CspMode::Standard;

        let report = Enforcer::evaluate(&manifest);

        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.id == "TS1008"));
    }
}
