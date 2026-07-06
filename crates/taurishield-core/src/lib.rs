use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use url::Url;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Manifest {
    pub application: Application,
    pub source: Source,
    pub security: Security,
    pub allowlist: Allowlist,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Application {
    pub name: String,
    pub identifier: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Source {
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Security {
    pub profile: SecurityProfile,
    pub csp: CspMode,
    pub permissions: Permissions,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    Strict,
    Standard,
    Kiosk,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CspMode {
    Strict,
    Standard,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Permissions {
    #[serde(default)]
    pub notifications: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub downloads: bool,
    #[serde(default)]
    pub shell: bool,
    #[serde(default)]
    pub filesystem: bool,
    #[serde(default)]
    pub camera: bool,
    #[serde(default)]
    pub microphone: bool,
    #[serde(default)]
    pub geolocation: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Allowlist {
    pub domains: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed to read manifest: {0}")]
    Read(String),
    #[error("failed to parse manifest: {0}")]
    Parse(String),
    #[error("source url must use https: {0}")]
    InsecureUrl(String),
    #[error("source url is invalid: {0}")]
    InvalidUrl(String),
    #[error("allowlist must contain at least one domain")]
    EmptyAllowlist,
    #[error("source host is missing")]
    MissingHost,
    #[error("source host must be present in allowlist: {0}")]
    SourceNotAllowlisted(String),
    #[error("allowlist domain must not include a scheme or path: {0}")]
    InvalidAllowlistDomain(String),
    #[error("application identifier must use reverse-DNS style: {0}")]
    InvalidIdentifier(String),
}

pub fn load_manifest(path: &Path) -> Result<Manifest, ManifestError> {
    let raw = fs::read_to_string(path).map_err(|e| ManifestError::Read(e.to_string()))?;
    let manifest: Manifest =
        serde_yaml::from_str(&raw).map_err(|e| ManifestError::Parse(e.to_string()))?;
    validate_manifest_basics(&manifest)?;
    Ok(manifest)
}

pub fn validate_manifest_basics(manifest: &Manifest) -> Result<(), ManifestError> {
    if !is_reverse_dns_identifier(&manifest.application.identifier) {
        return Err(ManifestError::InvalidIdentifier(
            manifest.application.identifier.clone(),
        ));
    }

    let url =
        Url::parse(&manifest.source.url).map_err(|e| ManifestError::InvalidUrl(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(ManifestError::InsecureUrl(manifest.source.url.clone()));
    }
    let host = url
        .host_str()
        .ok_or(ManifestError::MissingHost)?
        .to_string();

    if manifest.allowlist.domains.is_empty() {
        return Err(ManifestError::EmptyAllowlist);
    }

    for domain in &manifest.allowlist.domains {
        if domain.contains("://") || domain.contains('/') {
            return Err(ManifestError::InvalidAllowlistDomain(domain.clone()));
        }
    }

    if !manifest
        .allowlist
        .domains
        .iter()
        .any(|d| domain_matches(&host, d))
    {
        return Err(ManifestError::SourceNotAllowlisted(host));
    }
    Ok(())
}

pub fn domain_matches(host: &str, allowlisted: &str) -> bool {
    if let Some(suffix) = allowlisted.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == allowlisted
}

fn is_reverse_dns_identifier(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && part
                .chars()
                .next()
                .map(|c| c.is_ascii_alphanumeric())
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> Manifest {
        Manifest {
            application: Application {
                name: "ChatGPT".to_string(),
                identifier: "br.com.taurishield.chatgpt".to_string(),
                version: "0.3.0-beta.1".to_string(),
            },
            source: Source {
                url: "https://chatgpt.com".to_string(),
            },
            security: Security {
                profile: SecurityProfile::Strict,
                csp: CspMode::Strict,
                permissions: Permissions::default(),
            },
            allowlist: Allowlist {
                domains: vec!["chatgpt.com".to_string()],
            },
        }
    }

    #[test]
    fn exact_domain_matches() {
        assert!(domain_matches("chatgpt.com", "chatgpt.com"));
        assert!(!domain_matches("evilchatgpt.com", "chatgpt.com"));
    }

    #[test]
    fn wildcard_domain_matches_subdomain_and_root() {
        assert!(domain_matches("api.openai.com", "*.openai.com"));
        assert!(domain_matches("openai.com", "*.openai.com"));
        assert!(!domain_matches("openai.com.evil.test", "*.openai.com"));
    }

    #[test]
    fn rejects_http_source() {
        let mut manifest = valid_manifest();
        manifest.source.url = "http://chatgpt.com".to_string();
        assert!(matches!(
            validate_manifest_basics(&manifest),
            Err(ManifestError::InsecureUrl(_))
        ));
    }

    #[test]
    fn rejects_source_not_in_allowlist() {
        let mut manifest = valid_manifest();
        manifest.allowlist.domains = vec!["example.com".to_string()];
        assert!(matches!(
            validate_manifest_basics(&manifest),
            Err(ManifestError::SourceNotAllowlisted(_))
        ));
    }

    #[test]
    fn rejects_invalid_allowlist_domain_with_scheme() {
        let mut manifest = valid_manifest();
        manifest.allowlist.domains = vec!["https://chatgpt.com".to_string()];
        assert!(matches!(
            validate_manifest_basics(&manifest),
            Err(ManifestError::InvalidAllowlistDomain(_))
        ));
    }

    #[test]
    fn rejects_non_reverse_dns_identifier() {
        let mut manifest = valid_manifest();
        manifest.application.identifier = "chatgpt".to_string();
        assert!(matches!(
            validate_manifest_basics(&manifest),
            Err(ManifestError::InvalidIdentifier(_))
        ));
    }
}
