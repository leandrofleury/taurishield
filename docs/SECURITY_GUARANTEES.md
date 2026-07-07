# TauriShield Security Guarantees

TauriShield is designed to generate secure-by-default Tauri wrappers for web applications.

These guarantees define the minimum security baseline that every generated project must preserve.

## Core Guarantees

### 1. Global Tauri API Disabled

Generated projects must always set:

```json
"withGlobalTauri": false