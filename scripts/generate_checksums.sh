#!/usr/bin/env bash
set -euo pipefail
TARGET_DIR="${1:-dist}"
if [ ! -d "$TARGET_DIR" ]; then
  echo "Target directory not found: $TARGET_DIR" >&2
  exit 1
fi
find "$TARGET_DIR" -type f -print0 | sort -z | xargs -0 sha256sum > "$TARGET_DIR/SHA256SUMS"
echo "Checksums written to $TARGET_DIR/SHA256SUMS"
