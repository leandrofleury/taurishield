use anyhow::{Context, Result};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use taurishield_core::{CspMode, Manifest, SecurityProfile};

#[derive(Debug, Clone)]
pub struct BuildOutput {
    pub root_dir: PathBuf,
    pub tauri_conf: PathBuf,
    pub capabilities: PathBuf,
}

pub fn generate_tauri_project(manifest: &Manifest, output_base: &Path) -> Result<BuildOutput> {
    let safe_name = sanitize_dir_name(&manifest.application.name);
    let root_dir = output_base.join(safe_name);
    let src_tauri = root_dir.join("src-tauri");
    let caps_dir = src_tauri.join("capabilities");
    let src_dir = src_tauri.join("src");
    let ui_dir = root_dir.join("src");

    fs::create_dir_all(&caps_dir).context("failed to create capabilities directory")?;
    fs::create_dir_all(&src_dir).context("failed to create Rust source directory")?;
    fs::create_dir_all(&ui_dir).context("failed to create UI source directory")?;

    fs::write(root_dir.join("package.json"), package_json(manifest))?;
    fs::write(root_dir.join("index.html"), index_html(manifest))?;
    fs::write(ui_dir.join("main.js"), main_js(manifest))?;
    fs::write(src_tauri.join("Cargo.toml"), cargo_toml(manifest))?;
    fs::write(src_dir.join("main.rs"), main_rs(manifest))?;

    let tauri_conf = src_tauri.join("tauri.conf.json");
    let capabilities = caps_dir.join("default.json");
    fs::write(&tauri_conf, tauri_conf_json(manifest)?)?;
    fs::write(&capabilities, capability_json(manifest)?)?;
    fs::write(
        root_dir.join("TAURISHIELD_BUILD_NOTES.md"),
        build_notes(manifest),
    )?;

    Ok(BuildOutput {
        root_dir,
        tauri_conf,
        capabilities,
    })
}

fn sanitize_dir_name(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' || ch == ' ' {
            out.push('-');
        }
    }
    let normalized = out
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if normalized.is_empty() {
        "app".to_string()
    } else {
        normalized
    }
}

fn package_json(manifest: &Manifest) -> String {
    format!(
        r#"{{
  "name": "{}",
  "version": "{}",
  "private": true,
  "type": "module",
  "scripts": {{
    "dev": "tauri dev",
    "build": "tauri build"
  }},
  "devDependencies": {{
    "@tauri-apps/cli": "^2.0.0"
  }}
}}
"#,
        sanitize_dir_name(&manifest.application.name),
        manifest.application.version
    )
}

fn index_html(manifest: &Manifest) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{}</title>
  </head>
  <body>
    <noscript>TauriShield requires JavaScript to bootstrap the controlled WebView.</noscript>
    <main id="app">Loading {}</main>
    <script type="module" src="/src/main.js"></script>
  </body>
</html>
"#,
        manifest.application.name, manifest.application.name
    )
}

fn main_js(manifest: &Manifest) -> String {
    format!(
        r#"const target = {};

// TauriShield intentionally keeps the local UI minimal.
// The remote application is loaded as the configured external URL by Tauri.
document.querySelector('#app').textContent = `Opening ${{target}}`;
window.location.replace(target);
"#,
        serde_json::to_string(&manifest.source.url).unwrap()
    )
}

fn cargo_toml(manifest: &Manifest) -> String {
    let notification_dep = if manifest.security.permissions.notifications {
        "tauri-plugin-notification = \"2\"\n"
    } else {
        ""
    };
    format!(
        r#"[package]
name = "{}"
version = "{}"
edition = "2021"
license = "MIT"

[build-dependencies]
tauri-build = {{ version = "2", features = [] }}

[dependencies]
tauri = {{ version = "2", features = [] }}
{}
"#,
        sanitize_dir_name(&manifest.application.name),
        manifest.application.version,
        notification_dep
    )
}

fn main_rs(manifest: &Manifest) -> String {
    let notification_setup = if manifest.security.permissions.notifications {
        ".plugin(tauri_plugin_notification::init())"
    } else {
        ""
    };
    format!(
        r#"#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {{
    tauri::Builder::default()
        {}
        .run(tauri::generate_context!())
        .expect("error while running TauriShield generated application");
}}
"#,
        notification_setup
    )
}

fn tauri_conf_json(manifest: &Manifest) -> Result<String> {
    let csp = match manifest.security.csp {
        CspMode::Strict => strict_csp(&manifest.allowlist.domains),
        CspMode::Standard => standard_csp(&manifest.allowlist.domains),
    };

    let kiosk = manifest.security.profile == SecurityProfile::Kiosk;
    let value = json!({
        "$schema": "https://schema.tauri.app/config/2",
        "productName": manifest.application.name,
        "version": manifest.application.version,
        "identifier": manifest.application.identifier,
        "build": {
            "beforeDevCommand": "",
            "beforeBuildCommand": "",
            "devUrl": manifest.source.url,
            "frontendDist": "../"
        },
        "app": {
            "withGlobalTauri": false,
            "windows": [{
                "title": manifest.application.name,
                "url": manifest.source.url,
                "width": 1200,
                "height": 800,
                "resizable": !kiosk,
                "fullscreen": kiosk
            }],
            "security": {
                "csp": csp,
                "capabilities": ["default"]
            }
        },
        "bundle": {
            "active": true,
            "targets": "all"
        },
        "plugins": {}
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn capability_json(manifest: &Manifest) -> Result<String> {
    let mut permissions: Vec<String> = Vec::new();
    if manifest.security.permissions.notifications {
        permissions.push("notification:default".to_string());
    }

    let remote_urls: Vec<String> = manifest
        .allowlist
        .domains
        .iter()
        .map(|d| {
            format!(
                "https://{}",
                d.trim_start_matches("https://")
                    .trim_start_matches("http://")
            )
        })
        .collect();

    let value = json!({
        "$schema": "../gen/schemas/desktop-schema.json",
        "identifier": "default",
        "description": "TauriShield generated minimum capability set.",
        "windows": ["main"],
        "remote": {
            "urls": remote_urls
        },
        "permissions": permissions
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn strict_csp(domains: &[String]) -> String {
    let urls = domains
        .iter()
        .map(|d| {
            format!(
                "https://{}",
                d.trim_start_matches("https://")
                    .trim_start_matches("http://")
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("default-src 'self' {urls}; script-src 'self' {urls}; style-src 'self' 'unsafe-inline' {urls}; img-src 'self' data: blob: {urls}; connect-src 'self' {urls}; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action {urls}")
}

fn standard_csp(domains: &[String]) -> String {
    let urls = domains
        .iter()
        .map(|d| {
            format!(
                "https://{}",
                d.trim_start_matches("https://")
                    .trim_start_matches("http://")
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("default-src 'self' {urls}; script-src 'self' 'unsafe-inline' {urls}; style-src 'self' 'unsafe-inline' {urls}; img-src 'self' data: blob: {urls}; connect-src 'self' {urls}; frame-ancestors 'none'; object-src 'none'")
}

fn build_notes(manifest: &Manifest) -> String {
    format!(
        r#"# TauriShield Build Notes

Generated from manifest for **{}**.

## Security defaults applied

- `withGlobalTauri` disabled
- No shell plugin generated
- No filesystem plugin generated
- No clipboard plugin generated
- Remote capability restricted to manifest allowlist
- CSP generated from manifest domains
- Auto updater disabled
- Telemetry disabled

## Source

- URL: `{}`
- Identifier: `{}`
- Security profile: `{:?}`

"#,
        manifest.application.name,
        manifest.source.url,
        manifest.application.identifier,
        manifest.security.profile
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use taurishield_core::{
        Allowlist, Application, CspMode, Permissions, Security, SecurityProfile, Source,
    };

    fn manifest() -> Manifest {
        Manifest {
            application: Application {
                name: "Chat GPT".to_string(),
                identifier: "br.com.taurishield.chatgpt".to_string(),
                version: "0.3.0-beta.1".to_string(),
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

    fn temp_output() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("taurishield-builder-test-{nonce}"))
    }

    #[test]
    fn generated_project_contains_expected_files() {
        let output = temp_output();
        let generated = generate_tauri_project(&manifest(), &output).unwrap();
        assert!(generated.root_dir.join("package.json").exists());
        assert!(generated.tauri_conf.exists());
        assert!(generated.capabilities.exists());
        assert!(generated.root_dir.join("src-tauri/src/main.rs").exists());
        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn generated_tauri_config_disables_global_tauri() {
        let output = temp_output();
        let generated = generate_tauri_project(&manifest(), &output).unwrap();
        let raw = fs::read_to_string(generated.tauri_conf).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["app"]["withGlobalTauri"], false);
        assert!(value["app"]["security"]["csp"]
            .as_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn generated_capabilities_only_include_notification_when_enabled() {
        let output = temp_output();
        let generated = generate_tauri_project(&manifest(), &output).unwrap();
        let raw = fs::read_to_string(generated.capabilities).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["permissions"][0], "notification:default");
        assert_eq!(value["remote"]["urls"][0], "https://chatgpt.com");
        let _ = fs::remove_dir_all(output);
    }
}
