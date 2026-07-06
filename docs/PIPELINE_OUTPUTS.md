# Pipeline Outputs

The CLI is designed to produce both human-readable and machine-readable outputs.

## Human output

```bash
cargo run -p taurishield -- audit manifests/chatgpt.yml
```

Used by developers during local review.

## JSON report

```bash
cargo run -p taurishield -- report manifests/chatgpt.yml --output taurishield-report.json
```

Used by CI/CD, dashboards and future policy gates.

The report contains:

- application name
- identifier
- version
- source URL
- policy findings
- build blocked status

This beta emits JSON and SARIF evidence. Future versions can add CycloneDX VEX and fully automated signed attestation output.
