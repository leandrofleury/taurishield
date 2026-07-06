# Threat Model

Methodology: STRIDE.

## Assets

- User session cookies
- Authentication tokens
- Local machine integrity
- Clipboard data
- Downloaded files
- Corporate application data
- Build pipeline secrets
- Release artifacts

## Trust boundaries

1. Remote web application to WebView
2. WebView to Tauri runtime
3. Manifest to generator
4. Build pipeline to release artifact
5. Developer workstation to CI/CD

## STRIDE summary

### Spoofing

Risk: malicious or typosquatted URL in manifest.

Controls:
- HTTPS required
- Domain allowlist
- Future certificate inspection

### Tampering

Risk: manifest modification enabling dangerous permissions.

Controls:
- Policy engine
- Git review
- Signed manifests planned

### Repudiation

Risk: no audit trail for generated artifacts.

Controls:
- Future build metadata
- Future signed SBOM

### Information Disclosure

Risk: clipboard, filesystem, downloads, or permissive WebView leaking data.

Controls:
- Permissions disabled by default
- CSP required
- Domain allowlist

### Denial of Service

Risk: wrapper hangs, malicious site consumes resources.

Controls:
- Future runtime limits
- Future watchdog profile

### Elevation of Privilege

Risk: WebView content reaches privileged Tauri APIs.

Controls:
- No shell by default
- No filesystem by default
- No global Tauri exposure planned
- Minimal plugin set
