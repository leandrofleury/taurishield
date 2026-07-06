$ErrorActionPreference = "Stop"

Write-Host "[TauriShield] Running local Windows checks..."

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace

cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json
cargo run -p taurishield -- sarif manifests/chatgpt.yml --output taurishield.sarif
cargo run -p taurishield -- release-check manifests/chatgpt.yml --output dist

Write-Host "[TauriShield] Local checks completed."
