# Contributing

TauriShield is security-first. Convenience must not silently weaken the baseline.

## Required local checks

Run before opening a pull request:

```bash
./scripts/local_check.sh
```

## Rules

- Do not add shell or filesystem plugins without an ADR.
- Do not introduce wildcard remote access.
- Do not relax CSP without updating the threat model.
- Do not add telemetry.
- Prefer pinned, minimal dependencies.
- Every new manifest field needs validation and tests.

## Pull request checklist

- [ ] Manifest validation updated when schema changes.
- [ ] Policy engine updated when risk changes.
- [ ] Builder output tested.
- [ ] Documentation updated.
- [ ] No new high or critical policy findings.
