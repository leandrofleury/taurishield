use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize)]
pub struct HardenReport {
    pub schema_version: &'static str,
    pub project_root: String,
    pub tauri_conf: Option<String>,
    pub findings: Vec<HardenFinding>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardenFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub file: String,
    pub message: String,
    pub recommendation: String,
}

pub fn inspect_tauri_project(project_root: &Path) -> Result<HardenReport> {
    let tauri_conf = find_tauri_conf(project_root);
    let mut findings = Vec::new();

    if let Some(conf_path) = &tauri_conf {
        inspect_tauri_conf(conf_path, &mut findings)?;
    } else {
        findings.push(HardenFinding {
            severity: "critical",
            code: "TS-HARDEN-NO-TAURI-CONFIG",
            file: project_root.display().to_string(),
            message: "No src-tauri/tauri.conf.json file was found.".to_string(),
            recommendation: "Run harden against the root of a Tauri project or generate a project with TauriShield.".to_string(),
        });
    }

    inspect_capabilities(project_root, &mut findings)?;

    let blocked = findings.iter().any(|f| matches!(f.severity, "high" | "critical"));
    Ok(HardenReport {
        schema_version: "taurishield.harden.v1",
        project_root: project_root.display().to_string(),
        tauri_conf: tauri_conf.map(|p| p.display().to_string()),
        findings,
        blocked,
    })
}

pub fn write_harden_report(report: &HardenReport, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn find_tauri_conf(project_root: &Path) -> Option<PathBuf> {
    let candidate = project_root.join("src-tauri").join("tauri.conf.json");
    if candidate.exists() { Some(candidate) } else { None }
}

fn inspect_tauri_conf(path: &Path, findings: &mut Vec<HardenFinding>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    let file = path.display().to_string();

    if value.pointer("/app/withGlobalTauri").and_then(Value::as_bool).unwrap_or(false) {
        findings.push(HardenFinding {
            severity: "high",
            code: "TS-HARDEN-GLOBAL-TAURI",
            file: file.clone(),
            message: "withGlobalTauri is enabled.".to_string(),
            recommendation: "Set app.withGlobalTauri to false unless a documented exception exists.".to_string(),
        });
    }

    match value.pointer("/app/security/csp") {
        None | Some(Value::Null) => findings.push(HardenFinding {
            severity: "high",
            code: "TS-HARDEN-CSP-MISSING",
            file: file.clone(),
            message: "CSP is missing or null.".to_string(),
            recommendation: "Define a restrictive CSP generated from an explicit allowlist.".to_string(),
        }),
        Some(Value::String(csp)) if csp.contains("*") => findings.push(HardenFinding {
            severity: "medium",
            code: "TS-HARDEN-CSP-WILDCARD",
            file: file.clone(),
            message: "CSP contains wildcard usage.".to_string(),
            recommendation: "Replace wildcard sources with explicit HTTPS origins.".to_string(),
        }),
        _ => {}
    }

    if value.pointer("/bundle/active").and_then(Value::as_bool) == Some(true) {
        // Informational only: bundling is expected for desktop distribution.
    }

    Ok(())
}

fn inspect_capabilities(project_root: &Path, findings: &mut Vec<HardenFinding>) -> Result<()> {
    let caps_dir = project_root.join("src-tauri").join("capabilities");
    if !caps_dir.exists() {
        findings.push(HardenFinding {
            severity: "medium",
            code: "TS-HARDEN-CAPABILITIES-MISSING",
            file: caps_dir.display().to_string(),
            message: "No capabilities directory found.".to_string(),
            recommendation: "Use explicit Tauri capabilities and keep permissions minimal.".to_string(),
        });
        return Ok(());
    }

    for entry in fs::read_dir(caps_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
        inspect_capability_file(&path, findings)?;
    }
    Ok(())
}

fn inspect_capability_file(path: &Path, findings: &mut Vec<HardenFinding>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    let file = path.display().to_string();

    if let Some(perms) = value.get("permissions").and_then(Value::as_array) {
        for perm in perms.iter().filter_map(Value::as_str) {
            if perm.contains("shell") {
                findings.push(HardenFinding {
                    severity: "critical",
                    code: "TS-HARDEN-SHELL-PERMISSION",
                    file: file.clone(),
                    message: format!("Shell-related permission detected: {perm}"),
                    recommendation: "Remove shell permissions. TauriShield baseline does not allow shell access.".to_string(),
                });
            }
            if perm.contains("fs") || perm.contains("filesystem") {
                findings.push(HardenFinding {
                    severity: "high",
                    code: "TS-HARDEN-FS-PERMISSION",
                    file: file.clone(),
                    message: format!("Filesystem-related permission detected: {perm}"),
                    recommendation: "Remove filesystem permissions or create a documented exception with path-level restrictions.".to_string(),
                });
            }
        }
    }

    if let Some(urls) = value.pointer("/remote/urls").and_then(Value::as_array) {
        for url in urls.iter().filter_map(Value::as_str) {
            if url == "*" || url.contains("*.*") || url == "https://*" || url == "https://*.*" {
                findings.push(HardenFinding {
                    severity: "critical",
                    code: "TS-HARDEN-REMOTE-WILDCARD",
                    file: file.clone(),
                    message: format!("Overly broad remote URL allowed: {url}"),
                    recommendation: "Replace with explicit HTTPS origins required by the application.".to_string(),
                });
            } else if url.contains('*') {
                findings.push(HardenFinding {
                    severity: "medium",
                    code: "TS-HARDEN-REMOTE-WILDCARD-SUBDOMAIN",
                    file: file.clone(),
                    message: format!("Wildcard remote URL detected: {url}"),
                    recommendation: "Prefer explicit hostnames for enterprise builds.".to_string(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project() -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("taurishield-harden-test-{nonce}"))
    }

    #[test]
    fn detects_global_tauri_and_missing_csp() {
        let root = temp_project();
        let src = root.join("src-tauri");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("tauri.conf.json"), r#"{"app":{"withGlobalTauri":true,"security":{"csp":null}}}"#).unwrap();
        let report = inspect_tauri_project(&root).unwrap();
        assert!(report.findings.iter().any(|f| f.code == "TS-HARDEN-GLOBAL-TAURI"));
        assert!(report.findings.iter().any(|f| f.code == "TS-HARDEN-CSP-MISSING"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn detects_shell_permission() {
        let root = temp_project();
        let caps = root.join("src-tauri/capabilities");
        fs::create_dir_all(&caps).unwrap();
        fs::create_dir_all(root.join("src-tauri")).unwrap();
        fs::write(root.join("src-tauri/tauri.conf.json"), r#"{"app":{"withGlobalTauri":false,"security":{"csp":"default-src 'self'"}}}"#).unwrap();
        fs::write(caps.join("default.json"), r#"{"permissions":["shell:allow-open"],"remote":{"urls":["https://*.*"]}}"#).unwrap();
        let report = inspect_tauri_project(&root).unwrap();
        assert!(report.findings.iter().any(|f| f.code == "TS-HARDEN-SHELL-PERMISSION"));
        assert!(report.findings.iter().any(|f| f.code == "TS-HARDEN-REMOTE-WILDCARD"));
        let _ = fs::remove_dir_all(root);
    }
}
