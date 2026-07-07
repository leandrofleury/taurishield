# Release Process

This document defines the release process for TauriShield.

## Versioning

TauriShield uses semantic versioning:

- `0.x`: experimental API and unstable manifest format.
- `1.0.0-rc.x`: release candidates for validating the stable manifest and release process.
- `1.x`: stable manifest format and stable CLI behavior.

Current release candidate: `v1.0.0-rc.2`.

## Release branches

Use a dedicated branch for release preparation:

```bash
git checkout main
git pull origin main
git checkout -b chore/v1.0-rc1-release-readiness
git push -u origin chore/v1.0-rc1-release-readiness
```

## Mandatory local gates

A release is blocked if any mandatory local gate fails:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Supply-chain gates

Run:

```bash
cargo deny check
cargo audit
cargo cyclonedx --format json --override-filename taurishield
```

Expected result:

- `cargo deny check` passes.
- `cargo audit` passes.
- CycloneDX SBOM is generated successfully.

Non-blocking note: `cargo deny` may report `license-not-encountered` warnings when a license is allowed in `deny.toml` but not currently present in the dependency tree. These warnings do not block the release unless the project policy changes.

## CLI validation gates

Run:

```bash
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json
cargo run -p taurishield -- sarif manifests/chatgpt.yml --output taurishield.sarif
cargo run -p taurishield -- release-check manifests/chatgpt.yml --output dist
```

The release is blocked if:

- `validate` fails for the secure example manifest.
- `build` or `release-check` fails.
- High/Critical security violations are found in the release example.
- JSON or SARIF output cannot be generated.

## GitHub Actions gates

The `Security Checks` workflow must pass on:

- the release preparation branch;
- the pull request branch;
- `main` after merge.

The workflow validates:

- Rust formatting;
- Clippy with `-D warnings`;
- workspace tests;
- example manifest validation;
- example manifest audit;
- JSON report generation;
- SARIF report generation;
- release evidence generation;
- `cargo audit`;
- `cargo deny check`;
- CycloneDX SBOM generation.

## Artifact integrity

Every release should publish:

- source archive;
- binary artifacts, when available;
- SHA256 checksums;
- CycloneDX SBOM;
- release notes;
- release evidence;
- signature/attestation when available.

## Tagging

Only tag after all local and CI gates pass.

```bash
git checkout main
git pull origin main
git tag -a v1.0.0-rc.2 -m "TauriShield v1.0.0-rc.2"
git push origin v1.0.0-rc.2
```

## Generated application warning

TauriShield validates and generates hardened wrappers, but the remote web application remains part of the risk model. A compromised remote origin can still compromise user data within that origin.
