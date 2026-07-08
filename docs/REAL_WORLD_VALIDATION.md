# Real World Validation

This document records real-world runtime and packaging validation for TauriShield generated applications.

## Environment

- Host OS: Windows 11
- Runtime: WSL Ubuntu 26.04 with WSLg
- Rust: stable toolchain
- Node/npm: Linux-native Node/npm inside WSL
- Tauri: v2 generated application flow

## WSLg rendering fallback

The following environment variables were used when needed:

- WEBKIT_DISABLE_DMABUF_RENDERER=1
- LIBGL_ALWAYS_SOFTWARE=1
- MESA_LOADER_DRIVER_OVERRIDE=llvmpipe
- GSK_RENDERER=cairo

## Validated applications

| Application | Manifest | Dev runtime | Production build | Notes |
|---|---|---:|---:|---|
| ChatGPT | manifests/chatgpt.yml | OK | OK | WebView opened successfully |
| Gemini | manifests/gemini.yml | OK | OK | WebView opened successfully |
| Claude | manifests/claude.yml | OK | OK | WebView opened successfully |
| CrowdStrike Falcon US-2 | manifests/crowdstrike.yml | OK | OK | Login/dashboard opened successfully |

## Commands used

Generate applications:

- cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
- cargo run -p taurishield -- build manifests/gemini.yml --output dist
- cargo run -p taurishield -- build manifests/claude.yml --output dist
- cargo run -p taurishield -- build manifests/crowdstrike.yml --output dist

Run development mode:

- npm install
- npm run dev

Run production build:

- npm run build

## Result

The generated applications were validated beyond CI:

- generated project structure is valid;
- generated src-tauri project compiles;
- generated apps run in Tauri dev mode;
- generated apps load real remote web applications;
- generated apps build production Linux bundles;
- generated frontend assets are isolated from src-tauri, target, and node_modules.

## Security note

Do not commit screenshots containing tenant data, hostnames, detections, usernames, customer information, or authenticated console content.
