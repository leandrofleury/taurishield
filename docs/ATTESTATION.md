# Attestation and Signing Baseline

TauriShield beta treats release evidence as part of the product, not an afterthought.

## Required release evidence

- Generated Tauri project
- Audit JSON report
- SARIF report
- SBOM in CycloneDX JSON format
- SHA256 checksums
- Build logs
- Signed artifacts or corporate signing evidence
- Provenance attestation

## Recommended tooling

- `cosign sign-blob` for detached signatures
- `cosign attest-blob` for provenance
- `cyclonedx-bom` for SBOM
- `cargo audit` for known Rust vulnerabilities
- `cargo deny` for licenses, advisories, bans and duplicate dependency control

## Corporate mode

For internal use, signing may be delegated to the organization's code-signing workflow. The release checklist must still reference where the signing evidence is stored.
