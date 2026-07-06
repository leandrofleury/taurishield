use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use taurishield_analyzer::{analyze_url, write_manifest_from_analysis};
use taurishield_builder::generate_tauri_project;
use taurishield_core::load_manifest;
use taurishield_harden::{inspect_tauri_project, write_harden_report};
use taurishield_policy::{evaluate_manifest, Finding, Severity};

#[derive(Parser)]
#[command(name = "taurishield")]
#[command(about = "Secure Web Application Wrapper", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Validate {
        manifest: PathBuf,
    },
    Audit {
        manifest: PathBuf,
    },
    Report {
        manifest: PathBuf,
        #[arg(short, long, default_value = "taurishield-report.json")]
        output: PathBuf,
    },
    Sarif {
        manifest: PathBuf,
        #[arg(short, long, default_value = "taurishield.sarif")]
        output: PathBuf,
    },
    Build {
        manifest: PathBuf,
        #[arg(short, long, default_value = "dist")]
        output: PathBuf,
    },
    ReleaseCheck {
        manifest: PathBuf,
        #[arg(short, long, default_value = "dist")]
        output: PathBuf,
    },
    Analyze {
        url: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        identifier: Option<String>,
        #[arg(short, long, default_value = "generated-manifest.yml")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Harden {
        project: PathBuf,
        #[arg(short, long, default_value = "taurishield-harden-report.json")]
        output: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct AuditReport {
    schema_version: &'static str,
    application: String,
    identifier: String,
    version: String,
    source_url: String,
    findings: Vec<Finding>,
    blocked: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { manifest } => {
            let parsed = load_manifest(&manifest)?;
            println!("Manifest is valid: {}", parsed.application.name);
        }
        Commands::Audit { manifest } => {
            let parsed = load_manifest(&manifest)?;
            let findings = evaluate_manifest(&parsed);
            print_findings_or_ok(&findings);
            block_on_high_or_critical(&findings)?;
        }
        Commands::Report { manifest, output } => {
            let parsed = load_manifest(&manifest)?;
            let findings = evaluate_manifest(&parsed);
            let blocked = has_blocking_findings(&findings);
            let report = AuditReport {
                schema_version: "taurishield.audit.v1",
                application: parsed.application.name,
                identifier: parsed.application.identifier,
                version: parsed.application.version,
                source_url: parsed.source.url,
                findings,
                blocked,
            };
            std::fs::write(&output, serde_json::to_string_pretty(&report)?)?;
            println!("Audit report written to {}", output.display());
        }
        Commands::Sarif { manifest, output } => {
            let parsed = load_manifest(&manifest)?;
            let findings = evaluate_manifest(&parsed);
            let sarif = sarif_report(&manifest, &findings)?;
            std::fs::write(&output, sarif)?;
            println!("SARIF report written to {}", output.display());
            block_on_high_or_critical(&findings)?;
        }
        Commands::Build { manifest, output } => {
            let parsed = load_manifest(&manifest)?;
            let findings = evaluate_manifest(&parsed);
            print_findings_or_ok(&findings);
            block_on_high_or_critical(&findings)?;

            let generated = generate_tauri_project(&parsed, &output)?;
            println!("Generated Tauri project: {}", generated.root_dir.display());
            println!("Generated config: {}", generated.tauri_conf.display());
            println!(
                "Generated capabilities: {}",
                generated.capabilities.display()
            );
            println!(
                "Next: cd {} && pnpm install && pnpm tauri build",
                generated.root_dir.display()
            );
        }
        Commands::ReleaseCheck { manifest, output } => {
            let parsed = load_manifest(&manifest)?;
            let findings = evaluate_manifest(&parsed);
            print_findings_or_ok(&findings);
            block_on_high_or_critical(&findings)?;
            let generated = generate_tauri_project(&parsed, &output)?;
            let release_dir = generated.root_dir.join("release-evidence");
            std::fs::create_dir_all(&release_dir)?;
            std::fs::write(
                release_dir.join("taurishield-report.json"),
                serde_json::to_string_pretty(&AuditReport {
                    schema_version: "taurishield.audit.v1",
                    application: parsed.application.name,
                    identifier: parsed.application.identifier,
                    version: parsed.application.version,
                    source_url: parsed.source.url,
                    findings,
                    blocked: false,
                })?,
            )?;
            std::fs::write(
                release_dir.join("RELEASE_CHECKLIST.md"),
                release_checklist(),
            )?;
            println!("Release evidence generated at {}", release_dir.display());
        }
        Commands::Analyze {
            url,
            name,
            identifier,
            output,
            json,
        } => {
            let analysis = analyze_url(&url, name.as_deref(), identifier.as_deref())?;
            write_manifest_from_analysis(&analysis, &output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&analysis)?);
            } else {
                println!("Analyzed URL: {}", analysis.normalized_url);
                println!("Suggested manifest written to {}", output.display());
                println!("Risk score: {}/100", analysis.risk_score);
                if analysis.findings.is_empty() {
                    println!("No analysis findings detected.");
                } else {
                    for finding in &analysis.findings {
                        println!(
                            "{} [{}] {}",
                            finding.severity, finding.code, finding.message
                        );
                    }
                }
                println!("Next: taurishield validate {}", output.display());
            }
        }
        Commands::Harden { project, output } => {
            let report = inspect_tauri_project(&project)?;
            write_harden_report(&report, &output)?;
            println!("Harden report written to {}", output.display());
            if report.findings.is_empty() {
                println!("No hardening findings detected.");
            } else {
                for finding in &report.findings {
                    println!(
                        "{} [{}] {}",
                        finding.severity, finding.code, finding.message
                    );
                }
            }
            if report.blocked {
                anyhow::bail!("Hardening report contains high or critical findings.");
            }
        }
    }

    Ok(())
}

fn print_findings_or_ok(findings: &[Finding]) {
    if findings.is_empty() {
        println!("No policy findings detected.");
        return;
    }
    for finding in findings {
        println!(
            "{:?} [{}] {}",
            finding.severity, finding.code, finding.message
        );
    }
}

fn has_blocking_findings(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High | Severity::Critical))
}

fn block_on_high_or_critical(findings: &[Finding]) -> Result<()> {
    if has_blocking_findings(findings) {
        anyhow::bail!("Operation blocked by high or critical policy findings.");
    }
    Ok(())
}

fn sarif_report(manifest_path: &Path, findings: &[Finding]) -> Result<String> {
    let rules: Vec<_> = findings.iter().map(|f| {
        serde_json::json!({
            "id": f.code,
            "name": f.code,
            "shortDescription": { "text": f.message },
            "helpUri": "https://github.com/taurishield/taurishield/blob/main/docs/SECURITY_PROFILES.md"
        })
    }).collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.code,
                "level": sarif_level(&f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": manifest_path.to_string_lossy() },
                        "region": { "startLine": 1 }
                    }
                }]
            })
        })
        .collect();

    let value = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TauriShield Policy Engine",
                    "informationUri": "https://github.com/taurishield/taurishield",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn release_checklist() -> &'static str {
    r#"# TauriShield Release Checklist

- [ ] Manifest validated
- [ ] Policy audit has no High/Critical findings
- [ ] Generated Tauri configuration reviewed
- [ ] Capabilities reviewed
- [ ] `cargo fmt --check` completed
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` completed
- [ ] `cargo test --workspace` completed
- [ ] `cargo audit` completed
- [ ] `cargo deny check` completed
- [ ] SBOM generated
- [ ] Build artifact hashes generated
- [ ] Artifact signed with Cosign/Sigstore or corporate signing process
- [ ] Attestation generated
- [ ] Release notes reviewed
"#
}
