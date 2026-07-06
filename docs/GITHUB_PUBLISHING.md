# GitHub Publishing Guide

## Antes do primeiro push

1. Revisar `Cargo.toml` e ajustar `repository`.
2. Revisar `README.md`.
3. Criar repositório vazio no GitHub.
4. Confirmar licença MIT.
5. Executar checks locais.

```bash
cargo check
cargo test
./scripts/local_check.sh
```

## Primeiro commit

```bash
git init
git add .
git commit -m "Initial TauriShield release candidate"
git branch -M main
git remote add origin git@github.com:<user>/taurishield.git
git push -u origin main
```

## Release candidate

```bash
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

## Descrição curta do repositório

Secure Web Application Wrapper for Tauri with manifest validation, CSP generation, policy checks, SARIF, SBOM and release evidence.

## Tópicos sugeridos

- tauri
- rust
- appsec
- supply-chain-security
- secure-by-default
- webview
- desktop-app
- csp
- sarif
- sbom
