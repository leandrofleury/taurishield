# TauriShield Security Baseline

## TS-BL-001: HTTPS only
All wrapped applications must use HTTPS.

## TS-BL-002: Explicit allowlist
Every allowed remote domain must be explicitly declared.

## TS-BL-003: No shell
Shell access is prohibited in the default profile.

## TS-BL-004: No filesystem
Filesystem access is prohibited in the default profile.

## TS-BL-005: No global privileged bridge
Privileged Tauri APIs must not be globally exposed to remote content.

## TS-BL-006: No telemetry
No telemetry is permitted by default.

## TS-BL-007: No auto-update by default
Automatic updates are disabled until a signed update channel is implemented.
