# Architecture Decision Records

## ADR-0001: Manifest-driven build

Status: accepted

TauriShield uses a YAML manifest as the source of truth for application identity, source URL, permissions and domain allowlist.

Reason: keeps security configuration reviewable and versionable.

## ADR-0002: Deny shell access by default

Status: accepted

Shell access is disabled by default and treated as a high-risk permission.

Reason: shell access can turn a web compromise into local command execution.

## ADR-0003: Deny filesystem access by default

Status: accepted

Filesystem access is disabled by default.

Reason: most web wrappers do not require local file access.

## ADR-0004: Require HTTPS

Status: accepted

All source URLs must use HTTPS.

Reason: desktop wrappers should not package plaintext web transport.
