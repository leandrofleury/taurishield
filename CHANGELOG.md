# Changelog

## 1.0.0-rc.1

- Promovido pacote para release candidate.
- Adicionada documentação de produto.
- Adicionado checklist de homologação.
- Adicionado guia Windows/WSL.
- Adicionado guia de publicação GitHub.
- Adicionado modelo de risco.
- Adicionados manifestos para Claude, Open WebUI, Wazuh, Snipe-IT e Portainer.
- Adicionado script `local_check.ps1`.
- Atualizada versão do workspace para `1.0.0-rc.1`.


## 0.3.0-beta.1

### Added

- `taurishield analyze <url>` command for offline URL-to-manifest bootstrap.
- `taurishield harden <project>` command for inspecting existing Tauri projects.
- New `taurishield-analyzer` crate.
- New `taurishield-harden` crate.
- Harden report schema: `taurishield.harden.v1`.
- Analyze report schema: `taurishield.analyze.v1`.
- Documentation for analyze and harden workflows.

### Security

- `harden` detects `withGlobalTauri: true`.
- `harden` detects missing/null CSP.
- `harden` detects shell and filesystem permissions in capabilities.
- `harden` detects broad remote wildcards such as `https://*.*`.
- `analyze` increases risk for non-HTTPS URLs and local/internal targets.

### Notes

- `analyze` is offline in this beta. It does not fetch headers or crawl third-party resources yet.
- `harden` is report-only in this beta. It does not rewrite projects automatically yet.

## 0.3.0-beta.1

Primeira versão beta do TauriShield.

### Added

- Comando `sarif` para integração com GitHub Advanced Security e pipelines compatíveis com SARIF.
- Comando `release-check` para gerar evidências mínimas de release.
- Relatório JSON com `schema_version`.
- Baseline de attestation e assinatura documentado.
- Manifests atualizados para versão beta.
- Workflow de release beta com SBOM, SARIF e evidências.

### Changed

- Versão do workspace atualizada para `0.3.0-beta.1`.
- Documentação ajustada para ciclo beta.

### Security

- Operações continuam bloqueando achados `High` e `Critical`.
- `shell`, `filesystem`, câmera, microfone e geolocalização seguem bloqueados pela política enterprise padrão.
