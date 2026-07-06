# Windows 11 Lab Setup

Este guia é para validar o TauriShield em notebook Windows 11, especialmente quando a máquina é corporativa.

## Recomendação prática

Para validar o código Rust/CLI, use WSL Ubuntu.

Para gerar binário Windows `.exe` ou `.msi`, use Windows nativo em VM/lab ou máquina pessoal.

## Validação via WSL Ubuntu

No PowerShell:

```powershell
wsl --install -d Ubuntu
```

Dentro do Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential curl pkg-config libssl-dev
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

Dentro do projeto:

```bash
cargo check
cargo test
cargo run -p taurishield -- validate manifests/chatgpt.yml
cargo run -p taurishield -- audit manifests/chatgpt.yml
cargo run -p taurishield -- report manifests/chatgpt.yml
cargo run -p taurishield -- sarif manifests/chatgpt.yml
cargo run -p taurishield -- release-check manifests/chatgpt.yml
```

## Build Windows nativo

Componentes necessários:

- Rust MSVC toolchain;
- Visual Studio Build Tools;
- Node.js LTS;
- pnpm;
- WebView2 Runtime;
- Tauri CLI.

Comandos típicos:

```powershell
rustup default stable-x86_64-pc-windows-msvc
node --version
npm install -g pnpm
cargo install tauri-cli --version '^2'
```

Depois:

```powershell
cargo run -p taurishield -- build manifests/chatgpt.yml --output dist
cd dist\chatgpt
pnpm install
pnpm tauri build
```

## Nota corporativa

Em notebook de empresa, evite instalar toolchain global sem autorização. Use WSL para validação e deixe build final para ambiente controlado.
