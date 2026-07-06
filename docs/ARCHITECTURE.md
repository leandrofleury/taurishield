# Architecture

## Purpose

TauriShield generates hardened desktop wrappers for web applications using Tauri. The project is designed around a manifest-driven workflow and a policy engine that blocks unsafe configurations before build time.

## Pipeline

```text
Manifest
  ↓
Schema validation
  ↓
Policy evaluation
  ↓
Template rendering
  ↓
Tauri build
  ↓
Audit artifacts
  ↓
Release
```

## Main components

### taurishield-core

Responsible for parsing and validating manifests.

### taurishield-policy

Responsible for evaluating security rules against a manifest.

### taurishield-cli

Command-line interface for validation, auditing and future build generation.

## Security boundaries

TauriShield treats each remote web application as untrusted content by default. A wrapper must never receive powerful local permissions unless explicitly approved by policy and threat model.

## Default deny decisions

- Shell: disabled
- Filesystem: disabled
- Clipboard: disabled
- Downloads: disabled
- Camera: disabled
- Microphone: disabled
- Geolocation: disabled
- Telemetry: disabled
