# Analyze Workflow

`taurishield analyze` bootstraps a secure manifest from a URL.

In v0.3 beta, this is intentionally offline and conservative. It parses the URL, normalizes it, extracts the host, creates an explicit allowlist, assigns the `strict` profile, disables optional permissions, and generates a starter manifest.

## Example

```bash
taurishield analyze https://chatgpt.com \
  --name ChatGPT \
  --identifier br.com.taurishield.chatgpt \
  --output manifests/chatgpt.generated.yml
```

## JSON output

```bash
taurishield analyze https://chatgpt.com --json
```

## Current checks

- HTTPS requirement.
- Host extraction.
- Local/internal target detection.
- Deep subdomain warning.
- Suggested strict manifest generation.

## Future checks

- Header inspection.
- Existing CSP evaluation.
- Redirect chain review.
- WebSocket discovery.
- Third-party resource discovery.
- Suggested minimal allowlist from observed network calls.
