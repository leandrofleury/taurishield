use serde::Serialize;
use taurishield_core::Manifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    Permission,
    Network,
    Csp,
    Allowlist,
    Identity,
    Capability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub id: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub title: &'static str,
    pub description: &'static str,
    pub fix: &'static str,
    pub reference: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationReport {
    pub passed: bool,
    pub score: u8,
    pub violations: Vec<Violation>,
}

impl EvaluationReport {
    pub fn has_blocking_violations(&self) -> bool {
        self.violations
            .iter()
            .any(|v| matches!(v.severity, Severity::Critical | Severity::High))
    }
}

pub struct Enforcer;

impl Enforcer {
    pub fn evaluate(manifest: &Manifest) -> EvaluationReport {
        let mut violations = Vec::new();

        if manifest.security.permissions.shell {
            violations.push(Violation {
                id: "TS1001",
                severity: Severity::Critical,
                category: Category::Permission,
                title: "Shell permission is forbidden",
                description: "Shell permissions can expose host command execution capabilities.",
                fix: "Remove shell permission from the manifest.",
                reference: "docs/SECURITY_GUARANTEES.md#3-no-shell-permissions",
            });
        }

        let score = calculate_score(&violations);

        EvaluationReport {
            passed: !violations
                .iter()
                .any(|v| matches!(v.severity, Severity::Critical | Severity::High)),
            score,
            violations,
        }
    }
}

fn calculate_score(violations: &[Violation]) -> u8 {
    let mut score: i32 = 100;

    for violation in violations {
        score -= match violation.severity {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 10,
            Severity::Low => 5,
            Severity::Info => 0,
        };
    }

    score.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use taurishield_core::{
        Allowlist, Application, CspMode, Permissions, Security, SecurityProfile, Source,
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
        assert_eq!(report.score, 60);
        assert_eq!(report.violations[0].id, "TS1001");
        assert_eq!(report.violations[0].severity, Severity::Critical);
    }
}
