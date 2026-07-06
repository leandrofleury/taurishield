# TauriShield

**Secure Web Application Wrapper** — empacotador desktop baseado em Tauri v2 com postura **security-first**.

O TauriShield foi criado para transformar aplicações web em aplicativos desktop com controles mínimos obrigatórios: manifesto declarativo, allowlist de domínios, CSP gerado, capabilities restritivas, auditoria, SARIF, relatório JSON, SBOM e processo de release com evidências.

> Se o Pake prioriza velocidade e conveniência, o TauriShield prioriza controle, rastreabilidade e mínimo privilégio.

## Status

Versão: **1.0.0-rc.1**

Este pacote é um **Release Candidate**. Ele já está estruturado como produto publicável, mas ainda deve ser compilado e testado localmente com `cargo` antes de uso real.

## Recursos principais

- CLI `taurishield`
- Manifestos YAML por aplicação
- Validação de manifesto
- Policy Engine
- Build generator para projeto Tauri
- CSP gerado a partir da allowlist
- `withGlobalTauri: false`
- Bloqueio de shell/filesystem/sensíveis por padrão
- Relatório JSON
- Relatório SARIF
- Release check com evidências
- Analyzer inicial de URL
- Harden scanner para projetos Tauri existentes
- Documentação de threat model, supply chain, release e hardening

## Comandos

```bash
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json
cargo run -p taurishield -- sarif manifests/chatgpt.yml --output taurishield.sarif
cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
cargo run -p taurishield -- release-check manifests/chatgpt.yml --output dist
cargo run -p taurishield -- analyze https://chatgpt.com --output manifests/chatgpt.generated.yml
cargo run -p taurishield -- harden ./dist/chatgpt --output harden-report.json
```

## Baseline de segurança

Por padrão, o TauriShield considera bloqueantes:

- `shell: true`
- `filesystem: true`
- câmera, microfone ou geolocalização
- CSP incompatível com perfil strict/kiosk
- wildcard global de domínio
- source URL fora da allowlist
- HTTP sem TLS

## Manifesto exemplo

```yaml
application:
  name: ChatGPT
  identifier: br.com.taurishield.chatgpt
  version: 1.0.0

source:
  url: https://chatgpt.com

security:
  profile: strict
  csp: strict
  permissions:
    notifications: true
    clipboard: false
    downloads: false
    shell: false
    filesystem: false
    camera: false
    microphone: false
    geolocation: false

allowlist:
  domains:
    - chatgpt.com
    - auth.openai.com
    - '*.openai.com'
```

## Instalação para desenvolvimento

### Linux/WSL

```bash
sudo apt update
sudo apt install -y build-essential curl pkg-config libssl-dev
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
cargo check
cargo test
```

### Windows 11

Para validar CLI/projeto, prefira WSL Ubuntu. Para gerar `.exe/.msi`, use Windows nativo com Rust MSVC, Visual Studio Build Tools, Node LTS, pnpm, WebView2 Runtime e Tauri CLI.

Veja: `docs/WINDOWS_LAB_SETUP.md`.

## Documentação essencial

- `docs/PRODUCT_OVERVIEW.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/HARDENING_GUIDE.md`
- `docs/SUPPLY_CHAIN.md`
- `docs/RELEASE.md`
- `docs/HOMOLOGATION_CHECKLIST.md`
- `docs/WINDOWS_LAB_SETUP.md`
- `docs/ROADMAP.md`

## Licença

MIT.
