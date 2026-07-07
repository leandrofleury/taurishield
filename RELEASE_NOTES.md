# TauriShield v1.0.0-rc.1 Release Notes

## Release status

TauriShield `v1.0.0-rc.1` is a release candidate focused on validating the secure-by-default architecture before a stable `v1.0.0` release.

This version is suitable for security review, local validation, CI validation, and controlled lab usage. It is not yet positioned as a final stable release.

## Highlights

- Secure Web Application Wrapper based on Tauri v2.
- Declarative YAML manifest per wrapped application.
- Security Enforcer integrated into `validate` and `build` flows.
- Build hard-fail when blocking security violations are detected.
- Secure-by-default generated Tauri configuration.
- Mandatory CSP model through manifest security profile.
- Explicit domain allowlist.
- Shell and filesystem permissions blocked by baseline policy.
- JSON report generation.
- SARIF report generation.
- Release evidence generation.
- Initial URL analyzer.
- Tauri hardening scanner for existing generated projects.
- GitHub Actions pipeline for quality, supply-chain checks, and SBOM generation.

## Security guarantees

The generated Tauri project is expected to preserve these guarantees:

- `withGlobalTauri: false`.
- CSP is always present.
- Shell access is not allowed.
- Filesystem access is not allowed.
- Remote wildcard origins are not allowed.
- Remote origins must use HTTPS.
- Manifest allowlist must be explicit.

## Release gates

The release candidate should only be considered valid when the following checks pass:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
cargo cyclonedx --format json --override-filename taurishield
```

The GitHub Actions workflow must also complete successfully on the release branch and on `main`.

## Known limitations

- This release validates and hardens the wrapper, not the remote web application itself.
- A compromised remote origin remains inside the threat model.
- Signing and attestation are documented as release expectations, but may still depend on the target operating system and release environment.
- The analyzer is intentionally conservative and should not be treated as a complete web security scanner.

## Upgrade notes

No migration path is required yet because this is the first release candidate.

## Recommended validation flow

```bash
./scripts/local_check.sh
cargo deny check
cargo audit
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
cargo run -p taurishield -- harden ./dist/chatgpt --output harden-report.json
```
