use serde_json::Value;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use taurishield_builder::generate_tauri_project;
use taurishield_core::{
    Allowlist, Application, CspMode, Manifest, Permissions, Security, SecurityProfile, Source,
};

fn test_manifest() -> Manifest {
    Manifest {
        application: Application {
            name: "Secure Test App".to_string(),
            identifier: "br.com.taurishield.securetest".to_string(),
            version: "1.0.0-rc.1".to_string(),
        },
        source: Source {
            url: "https://chatgpt.com".to_string(),
        },
        security: Security {
            profile: SecurityProfile::Strict,
            csp: CspMode::Strict,
            permissions: Permissions {
                notifications: true,
                ..Default::default()
            },
        },
        allowlist: Allowlist {
            domains: vec!["chatgpt.com".to_string(), "auth.openai.com".to_string()],
        },
    }
}

fn temp_output() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    std::env::temp_dir().join(format!("taurishield-security-regression-{nonce}"))
}

fn generated_files() -> (Value, Value) {
    let output = temp_output();
    let manifest = test_manifest();

    let generated = generate_tauri_project(&manifest, &output).unwrap();

    let tauri_conf_raw = fs::read_to_string(&generated.tauri_conf).unwrap();
    let capability_raw = fs::read_to_string(&generated.capabilities).unwrap();

    let tauri_conf: Value = serde_json::from_str(&tauri_conf_raw).unwrap();
    let capabilities: Value = serde_json::from_str(&capability_raw).unwrap();

    let _ = fs::remove_dir_all(output);

    (tauri_conf, capabilities)
}

#[test]
fn generated_config_must_disable_global_tauri() {
    let (tauri_conf, _) = generated_files();

    assert_eq!(
        tauri_conf["app"]["withGlobalTauri"], false,
        "Generated Tauri config must keep withGlobalTauri disabled"
    );
}

#[test]
fn generated_config_must_have_non_empty_csp() {
    let (tauri_conf, _) = generated_files();

    let csp = tauri_conf["app"]["security"]["csp"]
        .as_str()
        .expect("CSP must be present and must be a string");

    assert!(!csp.trim().is_empty(), "CSP must not be empty");
    assert_ne!(csp, "null", "CSP must not be null");
}

#[test]
fn generated_csp_must_include_security_baseline_directives() {
    let (tauri_conf, _) = generated_files();

    let csp = tauri_conf["app"]["security"]["csp"]
        .as_str()
        .expect("CSP must be present");

    assert!(csp.contains("default-src"));
    assert!(csp.contains("object-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("base-uri 'none'"));
}

#[test]
fn generated_capabilities_must_not_allow_shell() {
    let (_, capabilities) = generated_files();

    let permissions = capabilities["permissions"]
        .as_array()
        .expect("permissions must be an array");

    assert!(
        permissions
            .iter()
            .all(|p| !p.as_str().unwrap_or_default().starts_with("shell:")),
        "Generated capabilities must not include shell permissions"
    );
}

#[test]
fn generated_capabilities_must_not_allow_filesystem() {
    let (_, capabilities) = generated_files();

    let permissions = capabilities["permissions"]
        .as_array()
        .expect("permissions must be an array");

    assert!(
        permissions
            .iter()
            .all(|p| !p.as_str().unwrap_or_default().starts_with("fs:")),
        "Generated capabilities must not include filesystem permissions"
    );
}

#[test]
fn generated_remote_urls_must_not_use_wildcards() {
    let (_, capabilities) = generated_files();

    let urls = capabilities["remote"]["urls"]
        .as_array()
        .expect("remote.urls must be an array");

    assert!(!urls.is_empty(), "remote.urls must not be empty");

    for url in urls {
        let url = url.as_str().unwrap_or_default();

        assert!(
            !url.contains('*'),
            "Generated remote URL must not contain wildcard: {url}"
        );

        assert!(
            url.starts_with("https://"),
            "Generated remote URL must use HTTPS: {url}"
        );
    }
}

#[test]
fn generated_remote_urls_must_match_manifest_allowlist() {
    let (_, capabilities) = generated_files();

    let urls = capabilities["remote"]["urls"]
        .as_array()
        .expect("remote.urls must be an array");

    let actual: Vec<String> = urls
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();

    assert!(actual.contains(&"https://chatgpt.com".to_string()));
    assert!(actual.contains(&"https://auth.openai.com".to_string()));
}