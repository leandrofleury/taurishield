#!/usr/bin/env bash
set -euo pipefail
mkdir -p sbom
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo 'cargo-cyclonedx not installed. Install with: cargo install cargo-cyclonedx'
  exit 1
fi
cargo cyclonedx --format json --output-file sbom/taurishield.cdx.json
echo 'SBOM generated at sbom/taurishield.cdx.json'
