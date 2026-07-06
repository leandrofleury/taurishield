# Build Pipeline

The `build` command does not compile binaries directly in v0.3 beta. Instead, it generates a hardened Tauri project from a validated manifest.

Pipeline:

1. Read YAML manifest
2. Validate structural rules
3. Evaluate security policy
4. Block critical/high findings
5. Generate Tauri project
6. Generate `src-tauri/tauri.conf.json`
7. Generate `src-tauri/capabilities/default.json`
8. Generate minimal Rust entrypoint
9. Generate build notes

## Current restrictions

The generator intentionally does not enable:

- shell plugin
- filesystem plugin
- clipboard plugin
- updater
- arbitrary HTTP plugin
- OAuth plugin
- global shortcut plugin
- global Tauri JS object

## Next steps

- add signed release workflow
- add SBOM generation
- add `cargo audit`
- add `cargo deny`
- add policy profiles
- add generated project tests
