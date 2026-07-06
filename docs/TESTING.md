# Testing Strategy

## Test pyramid

TauriShield v0.3 beta uses three layers:

1. **Core unit tests** for manifest parsing, domain matching, and identifier validation.
2. **Policy unit tests** for blocked permissions and allowlist findings.
3. **Builder tests** for generated Tauri configuration, CSP, and capabilities.

## Security regression tests

Every permission that is blocked by default must have a regression test.

Required blocked permissions:

- shell
- filesystem
- camera
- microphone
- geolocation

Medium-risk permissions must generate findings:

- clipboard
- downloads
- wildcard subdomain allowlists

## Manual generated-app validation

After generating an app:

```bash
cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
cd dist/chatgpt
pnpm install
pnpm tauri build
```

Then manually inspect:

- `src-tauri/tauri.conf.json`
- `src-tauri/capabilities/default.json`
- `src-tauri/Cargo.toml`
- generated CSP
- generated plugins
