# Risk Model

O TauriShield usa uma lógica simples: permissões que criam ponte entre conteúdo web e sistema operacional são tratadas como risco elevado.

## Severidades

- Critical: recurso proibido no baseline enterprise.
- High: recurso sensível que bloqueia build/release.
- Medium: recurso permitido apenas com justificativa.
- Low: melhoria recomendada.
- Info: observação não bloqueante.

## Exemplos

| Controle | Severidade | Motivo |
|---|---:|---|
| shell | Critical | Permite interação perigosa com SO. |
| filesystem | High | Aumenta risco de exfiltração/manipulação local. |
| camera/microphone/geolocation | High | Permissões sensíveis e privacidade. |
| clipboard | Medium | Pode expor tokens/senhas. |
| downloads | Medium | Pode introduzir arquivos maliciosos. |
| wildcard global | Critical | Quebra o modelo de allowlist. |
| CSP ausente | High | Aumenta impacto de XSS e injeções. |
