use anyhow::{Context, Result};
use serde::Serialize;
use std::{fs, path::Path};
use taurishield_core::{
    Allowlist, Application, CspMode, Manifest, Permissions, Security, SecurityProfile, Source,
};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct UrlAnalysis {
    pub schema_version: &'static str,
    pub input_url: String,
    pub normalized_url: String,
    pub host: String,
    pub suggested_identifier: String,
    pub suggested_allowlist: Vec<String>,
    pub risk_score: u8,
    pub findings: Vec<AnalysisFinding>,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

pub fn analyze_url(
    input_url: &str,
    name: Option<&str>,
    identifier: Option<&str>,
) -> Result<UrlAnalysis> {
    let url = Url::parse(input_url).context("invalid URL")?;
    let host = url
        .host_str()
        .context("URL must include a host")?
        .to_string();
    let mut findings = Vec::new();
    let mut risk_score: u8 = 15;

    if url.scheme() != "https" {
        findings.push(AnalysisFinding {
            severity: "critical",
            code: "TS-ANALYZE-INSECURE-SCHEME",
            message: "URL does not use HTTPS. TauriShield requires HTTPS for generated manifests."
                .to_string(),
        });
        risk_score = risk_score.saturating_add(70);
    }

    if host == "localhost" || host.ends_with(".local") || host.starts_with("127.") {
        findings.push(AnalysisFinding {
            severity: "medium",
            code: "TS-ANALYZE-LOCAL-TARGET",
            message: "Local/internal target detected. Validate distribution scope and network trust boundary.".to_string(),
        });
        risk_score = risk_score.saturating_add(15);
    }

    if host.matches('.').count() >= 3 {
        findings.push(AnalysisFinding {
            severity: "low",
            code: "TS-ANALYZE-DEEP-SUBDOMAIN",
            message: "Deep subdomain detected. Prefer explicit allowlist entries and avoid broad wildcards.".to_string(),
        });
        risk_score = risk_score.saturating_add(5);
    }

    let app_name = name
        .map(str::to_string)
        .unwrap_or_else(|| title_from_host(&host));
    let suggested_identifier = identifier
        .map(str::to_string)
        .unwrap_or_else(|| format!("br.com.taurishield.{}", slug_from_host(&host)));

    let manifest = Manifest {
        application: Application {
            name: app_name,
            identifier: suggested_identifier.clone(),
            version: "0.3.0-beta.1".to_string(),
        },
        source: Source {
            url: normalized_url(&url),
        },
        security: Security {
            profile: SecurityProfile::Strict,
            csp: CspMode::Strict,
            permissions: Permissions {
                notifications: false,
                ..Default::default()
            },
        },
        allowlist: Allowlist {
            domains: vec![host.clone()],
        },
    };

    Ok(UrlAnalysis {
        schema_version: "taurishield.analyze.v1",
        input_url: input_url.to_string(),
        normalized_url: manifest.source.url.clone(),
        host: host.clone(),
        suggested_identifier,
        suggested_allowlist: vec![host],
        risk_score: risk_score.min(100),
        findings,
        manifest,
    })
}

pub fn write_manifest_from_analysis(analysis: &UrlAnalysis, output: &Path) -> Result<()> {
    let yaml = serde_yaml::to_string(&analysis.manifest)?;
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output, yaml)?;
    Ok(())
}

fn normalized_url(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized.to_string().trim_end_matches('/').to_string()
}

fn title_from_host(host: &str) -> String {
    host.split('.')
        .filter(|part| *part != "www")
        .next()
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => "WebApp".to_string(),
            }
        })
        .unwrap_or_else(|| "WebApp".to_string())
}

fn slug_from_host(host: &str) -> String {
    host.replace("www.", "")
        .split('.')
        .next()
        .unwrap_or("webapp")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_https_url_and_generates_manifest() {
        let analysis = analyze_url("https://chatgpt.com", None, None).unwrap();
        assert_eq!(analysis.host, "chatgpt.com");
        assert_eq!(analysis.manifest.allowlist.domains, vec!["chatgpt.com"]);
        assert_eq!(analysis.risk_score, 15);
    }

    #[test]
    fn insecure_scheme_increases_risk() {
        let analysis = analyze_url("http://example.com", None, None).unwrap();
        assert!(analysis.risk_score >= 80);
        assert!(analysis
            .findings
            .iter()
            .any(|f| f.code == "TS-ANALYZE-INSECURE-SCHEME"));
    }
}
