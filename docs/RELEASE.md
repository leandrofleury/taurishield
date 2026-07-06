# Release Process

## Versioning

Use semantic versioning:

- `0.x`: experimental API
- `1.x`: stable manifest format

## Release gates

A release is blocked if any gate fails:

```bash
./scripts/local_check.sh
cargo deny check
cargo audit
cargo cyclonedx --format json --output-file sbom/taurishield.cdx.json
```

## Artifact integrity

Every release should publish:

- source archive
- binary artifacts
- SHA256 checksums
- CycloneDX SBOM
- release notes
- signature/attestation when available

## Generated application warning

TauriShield validates and generates hardened wrappers, but the remote web application remains part of the risk model. A compromised remote origin can still compromise user data within that origin.
