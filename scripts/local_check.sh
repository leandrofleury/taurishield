#!/usr/bin/env bash
set -euo pipefail

printf '\n[1/10] cargo fmt\n'
cargo fmt --check

printf '\n[2/10] cargo clippy\n'
cargo clippy --workspace --all-targets -- -D warnings

printf '\n[3/10] cargo test\n'
cargo test --workspace

printf '\n[4/10] validate example manifests\n'
for manifest in manifests/*.yml; do
  echo "validating ${manifest}"
  cargo run -p taurishield -- validate "${manifest}"
done

printf '\n[5/10] audit example manifests\n'
for manifest in manifests/*.yml; do
  echo "auditing ${manifest}"
  cargo run -p taurishield -- audit "${manifest}"
done

printf '\n[6/10] generate JSON audit report\n'
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json

printf '\n[7/10] generate SARIF report\n'
cargo run -p taurishield -- sarif manifests/chatgpt.yml --output taurishield.sarif

printf '\n[8/10] generate release evidence\n'
cargo run -p taurishield -- release-check manifests/chatgpt.yml --output dist

printf '\n[9/10] optional cargo-deny\n'
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo 'cargo-deny not installed; skipping. Install with: cargo install cargo-deny'
fi

printf '\n[10/10] optional cargo-audit\n'
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo 'cargo-audit not installed; skipping. Install with: cargo install cargo-audit'
fi

printf '\nAll mandatory local checks completed.\n'


echo "[TauriShield] Running analyze smoke test"
cargo run -p taurishield -- analyze https://chatgpt.com --output /tmp/taurishield-chatgpt.generated.yml

echo "[TauriShield] Running harden smoke test against generated dist if present"
if [ -d "dist/chatgpt" ]; then
  cargo run -p taurishield -- harden dist/chatgpt --output /tmp/taurishield-harden-report.json || true
fi
