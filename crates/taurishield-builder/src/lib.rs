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
    let icons_dir = src_tauri.join("icons");
    let web_dir = root_dir.join("web");
    let ui_dir = web_dir.join("src");

    fs::create_dir_all(&caps_dir).context("failed to create capabilities directory")?;
    fs::create_dir_all(&src_dir).context("failed to create Rust source directory")?;
    fs::create_dir_all(&icons_dir).context("failed to create icons directory")?;
    fs::create_dir_all(&ui_dir).context("failed to create UI source directory")?;

    fs::write(root_dir.join("package.json"), package_json(manifest))?;
    fs::write(web_dir.join("index.html"), index_html(manifest))?;
    fs::write(ui_dir.join("main.js"), main_js(manifest))?;
    fs::write(src_tauri.join("Cargo.toml"), cargo_toml(manifest))?;
    fs::write(src_tauri.join("build.rs"), build_rs())?;
    fs::write(icons_dir.join("icon.png"), default_icon_png())?;
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
        r#"[workspace]

[package]
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

fn build_rs() -> &'static str {
    r#"fn main() {
    tauri_build::build()
}
"#
}

fn default_icon_png() -> &'static [u8] {
    &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 32, 0, 0, 0, 32, 8,
        6, 0, 0, 0, 115, 122, 122, 244, 0, 0, 0, 48, 73, 68, 65, 84, 120, 156, 237, 206, 33, 1, 0,
        0, 8, 3, 48, 98, 144, 128, 8, 244, 111, 6, 49, 110, 38, 230, 87, 61, 123, 73, 37, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 144, 14, 60, 3, 6, 204, 76, 70, 132, 194,
        16, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
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
            "frontendDist": "../web"
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
            "targets": "all",
            "icon": ["icons/icon.png"]
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
        assert!(generated.root_dir.join("web/index.html").exists());
        assert!(generated.root_dir.join("web/src/main.js").exists());
        assert!(generated.tauri_conf.exists());
        assert!(generated.capabilities.exists());
        assert!(generated.root_dir.join("src-tauri/src/main.rs").exists());
        assert!(generated.root_dir.join("src-tauri/build.rs").exists());
        assert!(generated.root_dir.join("src-tauri/icons/icon.png").exists());

        let cargo_toml =
            fs::read_to_string(generated.root_dir.join("src-tauri/Cargo.toml")).unwrap();
        assert!(cargo_toml.starts_with("[workspace]"));

        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn generated_tauri_config_disables_global_tauri() {
        let output = temp_output();
        let generated = generate_tauri_project(&manifest(), &output).unwrap();
        let raw = fs::read_to_string(generated.tauri_conf).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["build"]["frontendDist"], "../web");
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
