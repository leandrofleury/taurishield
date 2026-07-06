# Product Overview

## Nome

**TauriShield — Secure Web Application Wrapper**

## Proposta

O TauriShield é uma ferramenta para empacotar aplicações web como aplicativos desktop usando Tauri v2, aplicando controles de segurança antes da geração do projeto.

O produto não tenta ser o wrapper mais rápido. Ele tenta ser o wrapper mais seguro, auditável e adequado para ambientes corporativos.

## Problema resolvido

Ferramentas de empacotamento web-to-desktop costumam privilegiar conveniência:

- permissões amplas;
- allowlists frouxas;
- CSP ausente;
- builds pouco reproduzíveis;
- baixa rastreabilidade;
- ausência de relatórios para CI/CD.

O TauriShield inverte a lógica: primeiro valida, depois gera.

## Público-alvo

- times de AppSec;
- times de SecOps;
- empresas que precisam empacotar dashboards internos;
- equipes que usam Tauri e precisam revisar hardening;
- profissionais que desejam distribuir web apps com postura mínima de segurança.

## Casos de uso

- Empacotar ChatGPT, Claude, Grafana, Wazuh, Snipe-IT, Portainer e Open WebUI.
- Criar apps kiosk para dashboards internos.
- Auditar projetos Tauri existentes.
- Gerar evidências de release para pipeline corporativo.
- Produzir SARIF para integração com GitHub Security.

## Princípios

1. Secure by Default.
2. Mínimo privilégio.
3. Configuração explícita.
4. Sem shell por padrão.
5. Sem filesystem por padrão.
6. CSP obrigatório.
7. Allowlist restritiva.
8. Evidência antes de release.
9. Sem telemetria embutida.
10. Falhar fechado.
