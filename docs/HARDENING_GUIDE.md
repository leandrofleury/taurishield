# Hardening Guide

## Before build

Run:

```bash
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
```

## Rules

- Do not enable shell unless there is a formal ADR.
- Do not enable filesystem unless there is a formal ADR.
- Avoid wildcard domains.
- Prefer strict CSP.
- Keep manifests small and explicit.
- Never embed secrets in manifests.

## CI recommendations

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`
- `cargo deny`
- SBOM generation
- Release signing
