# Hosted upgrade verification

The hosted upgrade is implemented for review. **Public deployment is not yet
verified.** No real credentials, real-data migrations, commits, pushes or publishing
were performed. See [production runbook](production.md) for configuration and commands.

## Passed locally

Environment: Intel macOS 13.7.7, Python 3.13.7, PostgreSQL 14.18 (disposable UTF-8
databases), Node 24.22.2, and Google Chrome 156.0.8078.80. The existing Node
20.19.4 dashboard checks/build also passed; the hosted container targets Node 24.

- Full Python suite with hosted PostgreSQL and real optional browser tests:
  **215 passed**. Existing CLI, CheckSpec compatibility, replay, local SQLite,
  browser network isolation and mocked AI coverage remain passing.
- Final affected hosted suite after database privilege hardening: **24 passed**.
  Covers ownership, JWT validation, idempotency, concurrent claims, expired
  leases/fencing, actual worker-process termination, uncertain model calls,
  cancellation, retained budgets, quotas, atomic rate limits, DNS expiry/revocation,
  DNS rebinding, blocked redirects, safe usage accounting, immutable results,
  worker readiness and least-privilege runtime access.
- SQLite import dry run/apply preserves IDs, original specs and recheck history;
  conflicting imports fail without overwriting. Imported targets remain revoked.
  Real PostgreSQL `pg_dump`/`pg_restore` preserves scan/recheck history.
- Dashboard type checks, **5 unit tests**, production build, and credential-marker
  inspection of **99 built frontend files**, using Node 24.
- Normal hosted dashboard entry point against a separately running API and worker,
  served from an isolated copy of the standalone production output: create project,
  TXT verification, scan, evidence, export, API restart, reopen saved report,
  fix/recheck resolved, and unavailable target unverified. Uses real signed JWTs
  and JWKS validation with a test identity gateway and controlled DNS/target
  adapters. This does **not** verify a real OIDC authorization-code login.
- Hosted wheel installed outside the source checkout; packaged Alembic migration
  applied to a fresh disposable database. Wheel/source archive metadata and
  runtime resources checked. Compose/workflow YAML and whitespace checked.

The hosted browser path deliberately reports unavailable/unverified while keeping
the HTTP baseline. The deployment does not install Chromium or claim Linux browser
egress isolation. Local macOS browser coverage exercises the existing sandbox.

## Resolved verification failures

- Explicitly initialized test databases as UTF-8 after the host's default locale
  produced SQL_ASCII, which the PostgreSQL driver could not use correctly.
- Used binary dependency wheels on this older macOS host; a newer cryptography
  source build stalled. Reproducible setup commands include `--only-binary=:all:`.
- Preserved the collector's existing `timeout` argument after a compatibility test
  caught its omission from the dispatch-accounting wrapper.
- Moved the UI harness to ports 3100/3101 to avoid the user's existing port-3000
  server, and corrected project selection/recheck polling found by UI acceptance.
- Corrected Compose tmpfs YAML quoting; verified standalone assets from a separate
  directory rather than relying on files beside the build checkout.

No required locally executed check remains failing. One dependency deprecation
warning remains in FastAPI/Starlette's HTTPX test-client integration.

## Unrun checks and deployment blockers

- Docker/Compose builds and service startup: Docker is not installed on this host.
  Syntax validation and standalone execution are not substitutes for these checks.
- PostgreSQL **17**, the Compose target, including role initialization and restore
  with version-matched client tools. Local database tests used PostgreSQL 14.18.
- Real Keycloak/OAuth2 Proxy login, logout, refresh, expiry/revocation, forwarded
  headers and trusted HTTPS/cookies. Requires externally configured identity and
  secrets; no credentials or accounts were created.
- New GitHub Actions hosted job, container checks and platform matrix. Workflow
  changes are prepared locally and have not been pushed or run on GitHub.
- Deployment infrastructure egress/resource policy, secret provisioning, operational
  monitoring and backup/restore rehearsal on the actual target platform.
- A verified private security reporting route remains a release blocker; see
  [SECURITY.md](../SECURITY.md). No contact route has been invented.

Live OpenRouter calls were intentionally not made. Controlled mock responses cover
success/failure, baseline retention, accounting and uncertain billed-call recovery.
