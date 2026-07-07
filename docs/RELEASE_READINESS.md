# Release Readiness Checklist

Use this checklist to decide whether `v1.0.0-rc.1` is ready to be tagged, published, or merged into a release branch.

## 1. Repository hygiene

- [ ] `main` is green in GitHub Actions.
- [ ] Release branch is green in GitHub Actions.
- [ ] Working tree is clean.
- [ ] Generated artifacts are not committed.
- [ ] `.gitignore` covers `target/`, `dist/`, generated SBOM files, logs, and local environment files.
- [ ] `Cargo.lock` is committed.

## 2. Rust quality gates

Run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected result:

- [ ] Formatting passes.
- [ ] Clippy passes with zero warnings.
- [ ] Unit tests pass.
- [ ] Doc tests pass.

## 3. Supply-chain gates

Run:

```bash
cargo deny check
cargo audit
cargo cyclonedx --format json --override-filename taurishield
```

Expected result:

- [ ] Advisories check passes.
- [ ] Dependency bans check passes.
- [ ] License check passes.
- [ ] Source check passes.
- [ ] Audit check passes.
- [ ] CycloneDX SBOM is generated.

Notes:

- `cargo deny` warnings for allowed-but-not-encountered licenses are non-blocking unless the project policy changes.

## 4. Manifest validation gates

Run:

```bash
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json
cargo run -p taurishield -- sarif manifests/chatgpt.yml --output taurishield.sarif
```

Expected result:

- [ ] `validate` passes for secure manifest.
- [ ] `audit` reports no blocking High/Critical findings for release example.
- [ ] JSON report is generated.
- [ ] SARIF report is generated.

## 5. Security Enforcer gates

The Enforcer must block:

- [ ] `shell: true`.
- [ ] `filesystem: true`.
- [ ] wildcard allowlist entries such as `*`.
- [ ] non-HTTPS source URLs.
- [ ] source hosts outside the allowlist.
- [ ] strict/kiosk profile with non-strict CSP.

The Enforcer may warn without blocking for low-risk optional capabilities, depending on the selected profile.

## 6. Builder gates

Run:

```bash
cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
cargo run -p taurishield -- release-check manifests/chatgpt.yml --output dist
cargo run -p taurishield -- harden ./dist/chatgpt --output harden-report.json
```

Expected result:

- [ ] Generated project is created under `dist/`.
- [ ] Generated Tauri config keeps `withGlobalTauri: false`.
- [ ] Generated project has CSP.
- [ ] Generated capabilities do not include shell or filesystem.
- [ ] Release evidence is generated.
- [ ] Harden report does not identify blocking regressions.

## 7. Documentation gates

- [ ] README reflects current CLI commands.
- [ ] `docs/SECURITY_GUARANTEES.md` reflects implemented guarantees.
- [ ] `docs/RELEASE.md` reflects actual release process.
- [ ] `docs/HOMOLOGATION_CHECKLIST.md` reflects user-facing app validation.
- [ ] `RELEASE_NOTES.md` is updated.
- [ ] Known limitations are documented.

## 8. Tagging gate

Only tag after all previous gates pass.

Recommended tag command:

```bash
git tag -a v1.0.0-rc.1 -m "TauriShield v1.0.0-rc.1"
git push origin v1.0.0-rc.1
```

Do not tag if the branch has uncommitted changes or failing GitHub Actions.
