# Security policy

## Supported versions

0.1.0 is the first release candidate. No published version is currently promised
security maintenance. Once released, fixes will target the latest 0.1.x release;
older builds should be upgraded. Local v1 remains a single-user product. The new hosted v2 implementation is
prepared for review and has not been approved for public deployment; its external
OIDC/container/HTTPS verification gates remain open.

## Private reporting — release blocker

A working private reporting route has **not** been configured. On 2026-11-08,
the GitHub API for the actual public repository
[fuadhasandev/patchproof](https://github.com/fuadhasandev/patchproof) returned
`{"enabled": false}` for `/repos/fuadhasandev/patchproof/private-vulnerability-reporting`.
No existing security email or other private route was found in the repository.
Do not disclose vulnerabilities or sensitive evidence in public issues.

Before publishing 0.1.0, the maintainer must enable GitHub private vulnerability
reporting (or supply another verified private route), verify it works, and replace
this blocker with the confirmed reporting instructions. No contact address is
invented here.

## Boundaries

Only scan authorized targets. Keep the local v1 API and dashboard on loopback.
Hosted v2 requires verified exact-host targets, OIDC and private API/dashboard
networks behind the configured HTTPS/login ingress; see docs/production.md. Credentials,
query strings, fragments and nonpublic destinations are rejected; the explicit
local-fixture exception does not authorize LAN access. Browser egress isolation
is macOS-only and fails closed. CheckSpecs and model output cannot grant access.
Reports retain target paths and configured cookie names; do not put secrets in
paths. SQLite is private local storage, not encrypted storage. See README.md for
what is retained and what optional OpenRouter calls disclose.
