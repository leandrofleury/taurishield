#!/usr/bin/env bash
set -euo pipefail
ARTIFACT="${1:?usage: sign_artifact_cosign.sh <artifact>}"
cosign sign-blob --yes --output-signature "$ARTIFACT.sig" --output-certificate "$ARTIFACT.pem" "$ARTIFACT"
echo "Signature: $ARTIFACT.sig"
echo "Certificate: $ARTIFACT.pem"
