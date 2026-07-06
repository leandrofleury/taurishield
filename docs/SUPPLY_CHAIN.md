# Supply Chain Security

TauriShield is designed to be auditable before it is convenient.

## Default posture

- Rust dependencies must come from crates.io unless explicitly approved.
- Git dependencies are denied by default.
- Yanked crates are denied.
- Known vulnerable crates are denied.
- Wildcard dependency versions are denied.
- License policy is enforced with `cargo-deny`.
- SBOM generation is expected for release builds.
- Release artifacts should be signed outside the generated app template.

## Recommended local commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
cargo cyclonedx --format json --output-file sbom/taurishield.cdx.json
```

## Non-goals for v0.3 beta

- Automatic updates.
- Remote code fetching.
- Runtime plugin installation.
- Global shell/file-system permissions.
- Secret handling inside app manifests.

## Release checklist

1. Review manifest.
2. Run `taurishield audit`.
3. Run Rust quality gates.
4. Run SCA checks.
5. Generate SBOM.
6. Build in controlled CI.
7. Sign artifact.
8. Publish checksum and SBOM.
