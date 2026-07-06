# Harden Workflow

`taurishield harden` inspects an existing Tauri project and reports deviations from the TauriShield security baseline.

In v0.3 beta, this command is report-only. It does not modify files yet.

## Example

```bash
taurishield harden ./my-tauri-app --output harden-report.json
```

## Current checks

- Detects missing `src-tauri/tauri.conf.json`.
- Detects `app.withGlobalTauri: true`.
- Detects missing or null CSP.
- Detects wildcard usage in CSP.
- Detects shell-related permissions in capabilities.
- Detects filesystem-related permissions in capabilities.
- Detects broad remote wildcards such as `https://*.*`.

## Blocking logic

High and critical findings cause a non-zero exit status. This makes the command suitable for CI/CD gates.

## Future mode

A future release may include:

```bash
taurishield harden ./my-tauri-app --write
```

That mode should only apply deterministic, reviewable patches. No automatic security rewrite should happen silently.
