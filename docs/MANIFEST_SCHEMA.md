# Manifest Schema

The manifest is the source of truth for each generated desktop app.

```yaml
application:
  name: ChatGPT
  identifier: br.com.taurishield.chatgpt
  version: 0.3.0-beta.1

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
```

## Validation rules

- `source.url` must be HTTPS.
- `source.url` host must match the allowlist.
- `application.identifier` must follow reverse-DNS style.
- Allowlist entries must be hostnames only, not URLs.
- Global wildcards are blocked by policy.
- Shell and filesystem are blocked by policy.
