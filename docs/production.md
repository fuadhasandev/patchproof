# Hosted backend deployment

This change adds a hosted v2 backend while preserving the local v1 API, SQLite,
CLI commands, CheckSpec schemas 1–3 and replay exit codes. It is prepared for
review, **not approved for public deployment**. Docker execution and a real
Keycloak/OAuth2 Proxy login must pass in the deployment environment before launch.
No real credentials, public deployment or real-data migration were performed.

## Architecture

```mermaid
flowchart LR
  Browser --> HTTPS[HTTPS ingress]
  HTTPS --> Login[OAuth2 Proxy / OIDC]
  Login --> Dashboard[Next.js dashboard]
  Dashboard --> API[FastAPI v2 / JWT validation]
  API --> DB[(PostgreSQL)]
  Worker[Separate worker process] --> DB
  Worker --> Target[Verified public target]
  Worker --> Model[Optional OpenRouter]
```

The API submits work; it never scans targets or invokes models. SQLAlchemy Core
provides transactions and explicit foreign keys; Alembic owns schema revisions.
Users are unique by OIDC issuer/subject. Projects, exact-host targets, scan records,
jobs, findings, CheckSpecs and rechecks have explicit owners and project relations.
Composite foreign keys prevent cross-owner associations. Original findings/specs,
saved baselines and terminal jobs are immutable in PostgreSQL. Lists use bounded
keyset pagination (20 default, 50 maximum). The migration snapshot is frozen;
future changes require a new Alembic revision and matching runtime metadata.

Hosted endpoints live under `/v2`; local `/v1` remains on `patchproof.api:create_app`.
Do not expose the local API publicly or reuse its shared token for hosted access.
No SQLite database is automatically converted or opened by the hosted API.

## Required external configuration

Use an existing **Keycloak OIDC** realm and OAuth2 Proxy's maintained login flow.
The application does not implement passwords or its own authorization-code flow.
Create/configure these outside this code-preparation step:

- A confidential `patchproof-dashboard` client with standard authorization-code
  flow and S256 PKCE, exact HTTPS callback `<PUBLIC_ORIGIN>/oauth2/callback`, no
  wildcard redirects, and a client secret.
- Access tokens signed with RS256 containing `iss`, `aud`, `sub`, `iat`, `exp`.
  Configure an audience mapper for the dedicated **patchproof-api** audience.
  Do not add that audience to ID tokens. Keep access-token lifetimes short (for
  example five minutes). Verified-email claims are required by the login proxy.
- Issuer and explicit HTTPS JWKS URL. API validation fixes the algorithm,
  issuer/audience and required claims; token-supplied key URLs are never used.
  Keys are cached for up to five minutes; token revocation is bounded by token
  expiry rather than per-request introspection. Rotate keys with an overlap window.
- Independent database migration-owner/runtime passwords and a 32-byte base64
  cookie-encryption secret, supplied through your deployment secret mechanism.
  URL-encode passwords in database URLs. Never commit these values.
- An HTTPS hostname/ingress and trusted certificates. Optional OpenRouter key
  and tool-capable model ID belong to the **worker only**.

OAuth2 Proxy sets Secure, HttpOnly, SameSite=Lax `__Host-patchproof` cookies,
validates nonce, uses PKCE and per-request CSRF cookies, and replaces forwarded
access-token headers. The dashboard forwards that token server-side; the API
independently validates its signature/claims. Tokens never enter application
JavaScript or PostgreSQL. Dashboard mutations require the exact Host/Origin,
reject cross-site fetches and accept only explicit routes. API mutations independently
require the configured Origin and JSON. Request bodies are limited to 8 KiB.
There is no wildcard CORS. All routes except health probes require a valid JWT.

The login proxy is the only application ingress; API, dashboard and database have
no host ports. Do not bypass it with a public dashboard port. Strip incoming
`X-Forwarded-Access-Token` and Authorization headers at the outer ingress and
forward the original Host and HTTPS scheme. Restrict identity-provider realm access
to the intended users; `--email-domain=*` is not an authorization allowlist.

These settings follow [OAuth2 Proxy's Keycloak integration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/providers/keycloak_oidc/)
and [cookie/header/PKCE configuration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/).
JWT validation uses [PyJWT](https://pyjwt.readthedocs.io/en/stable/usage.html).

## Exact local production-mode startup

Prerequisites: Docker Engine/Compose v2, an externally configured OIDC client,
configured secrets, and Caddy for the local HTTPS example. The Compose targets
Python 3.13, Node 24, PostgreSQL 17 and OAuth2 Proxy 7.15.0. These image builds and
real login are not locally verified on this Docker-less machine; do not treat
successful YAML validation as a container/deployment test.

From the repository root:

```sh
cp .env.example .env.production
chmod 600 .env.production
# Edit .env.production: replace EVERY REPLACE_* value and identity URL.
# Set PATCHPROOF_PUBLIC_ORIGIN=https://patchproof.localhost:8443
# Set PATCHPROOF_OIDC_AUDIENCE to the access-token API audience.
# Configure the exact HTTPS callback in the identity provider first.
docker compose --env-file .env.production config --quiet
docker compose --env-file .env.production build api worker dashboard
docker compose --env-file .env.production up -d postgres
docker compose --env-file .env.production --profile ops run --rm migrate
docker compose --env-file .env.production up -d api worker dashboard login
```

In another terminal:

```sh
caddy run --config deployment/Caddyfile.local
```

Trust Caddy's local CA explicitly using your OS's supported procedure (`caddy trust`
when appropriate), then open **https://patchproof.localhost:8443**. Do not disable
TLS verification or secure cookies. OAuth2 Proxy listens on **127.0.0.1:4180**
behind this ingress; direct HTTP access is not the supported login workflow.
For a public deployment, replace the local Caddy example with your approved TLS
termination configuration and exact public origin/callback. Do not enable
`PATCHPROOF_HOSTED_DEV` publicly; it permits loopback HTTP infrastructure only
for controlled integration tests, never loopback scan targets.

The first PostgreSQL volume initialization creates a non-superuser runtime role.
Only the migration service receives the migration-owner database URL. Migration
execution grants the runtime role SELECT/INSERT/UPDATE and sequence access, not
DDL or database/role administration. Existing external PostgreSQL installations
must provision equivalent roles separately. Changing passwords in an env file
does not rotate existing database roles automatically.

For existing local development, keep the README commands and `PATCHPROOF_MODE=local`
(or unset). Nothing in this deployment changes `.patchproof/history.sqlite3`.

## Target verification and scanning

1. Sign in, create/select a project, and enter one exact DNS hostname.
2. Create a DNS challenge. Publish the returned random value as TXT at
   `_patchproof.<hostname>`, then click **Verify DNS**.
3. Select that target and submit an HTTP(S) URL for the same hostname.
4. Inspect evidence, download a CheckSpec, fix the target and click **Recheck**.
   Rechecks preserve the original finding. History survives API/worker restarts.

Challenges expire after 15 minutes; verified authorization expires after 24 hours
(defaults are configurable). Only the token hash is stored. Rotation invalidates
the old challenge and verification. Revocation takes effect before the next
reserved request. Authorization is bound to the user, project and **exact hostname**;
no implicit subdomain, unrelated host, LAN or loopback authorization is granted.
Verification does not pin a DNS answer: every connection still revalidates all
addresses and connects numerically with the original TLS SNI/Host. Redirects are
not followed. DNS rebinding, mixed public/private answers and private addresses
remain blocked. Hosted mode ignores all local-fixture exceptions.

DNS verification itself has a five-second resolver lifetime and shared per-user
limits. The normal system DNS resolver is used; deploy a trusted resolver.
Domain ownership is not evidence of authorization to attack arbitrary services;
the scanner remains limited to its existing deterministic GET checks.

Hosted browser execution is **deliberately unavailable on every hosted worker**,
including macOS. The Linux deployment has no verified Chromium egress boundary
and no browser dependency installed. A requested browser scan returns an
unverified `browser_result` while retaining the HTTP baseline. Schema-3 rechecks
also return unverified. Local macOS browser scanning remains supported separately.
Do not enable an interception-only browser fallback or mount the Docker socket.

## Queue, recovery and accounting

Claims use PostgreSQL row locks with `SKIP LOCKED`, a unique attempt lease token,
and database-clock expiry. Default concurrency is two threads in each separate
worker process; several worker processes may share the queue. Heartbeats renew a
60-second lease every ten seconds. Every result/checkpoint write checks the current
lease token and expiry, so an expired worker cannot overwrite a newer attempt.
The [PostgreSQL locking documentation](https://www.postgresql.org/docs/current/sql-select.html)
explains the queue-oriented use of `SKIP LOCKED`.

Before each HTTP or model dispatch, one transaction rechecks cancellation and
verification, consumes the persistent per-job budget, charges shared rate/usage
buckets and records an external-call reservation. Counters never reset across
attempts. Default limits are five target attempts, three model calls, three worker
attempts, ten submissions/minute/user, thirty target attempts/minute/user **and
hostname**, and one hundred model calls/day/user. Buckets use database time and
are shared across processes. Output-token caps are reserved alongside model calls;
validated provider token counts are retained when returned. Uncertain outcomes
have unknown billed usage, not zero cost. These are call/token limits, not a
currency spending guarantee; configure the provider account's spending limit too.

Infrastructure/worker interruptions without a dispatched model call requeue with
bounded exponential delay (2/4/8 seconds, capped at 30), retaining target budgets
and any saved baseline. Target network/HTTP failures finish as unverified rather
than automatically repeat a scan. A model error/timeout marks the call uncertain
and retains baseline results. A worker crash after any model dispatch becomes
**interrupted**, never automatically replays the investigation. Explicitly starting
a new scan is a new potentially billed operation. Hosted v2 has no automatic
"retry as a new job with fresh budget" endpoint.

Cancellation prevents new dispatches. An already dispatched HTTP/model request
may finish (and a model call may be billed); its cancellation cannot be guaranteed
by HTTP. The worker preserves its prior baseline and marks the job cancelled.
An in-flight request is not described as undone. SIGTERM stops claims and drains
accepted work; Compose allows 180 seconds before forced termination, after which
lease recovery applies. HTTP retains its five-second I/O deadline; model operation
timeouts default to 20 seconds, output to 2,048 tokens and response bytes to 256 KiB.
Model limits remain at most three turns/two follow-up target attempts and eight
validated tools/turn. HTTPX timeouts are operation timeouts, not an exactly-once
billing guarantee or an absolute investigation deadline.

The HTTP baseline is checkpointed before optional work. AI failure, unavailable
browser isolation, cancellation and infrastructure failure cannot fabricate a
resolved recheck. Read the deterministic result (`resolved`, `still_present`,
`unverified`) separately from job state/progress. A completed job can contain an
unverified result or failed AI status.

## API contract and observability

| Method/path | Operation |
| --- | --- |
| `GET /health/live`, `GET /health/ready` | Process liveness; schema/database plus recent worker heartbeat readiness |
| `GET /v2/me` | Current user ID and hosted browser availability |
| `GET/POST /v2/projects` | Owned project list/create |
| `GET/POST /v2/projects/{id}/targets` | Owned targets / rotate DNS challenge |
| `POST /v2/targets/{id}/verify`, `/revoke` | Verify TXT / revoke authorization |
| `POST /v2/scans` | Submit owned project/target scan |
| `GET /v2/projects/{id}/scans` | Persisted scan history |
| `GET /v2/jobs/{id}`, `POST /v2/jobs/{id}/cancel` | Progress/report / cancellation |
| `GET /v2/findings/{id}/spec` | Owned versioned export |
| `GET/POST /v2/findings/{id}/rechecks` | Timeline / submit recheck |
| `GET /v2/metrics` | Own job-state counts, external-call states, reported token usage, reserved output caps and healthy-worker count |

POST bodies are JSON and require the exact configured Origin. Scans accept the
v1 fields plus `project_id` and `target_id`; no user ID or network permission is
accepted. Scan/recheck submissions require an `Idempotency-Key` of 1–128 characters.
A key is unique per authenticated user and bound to normalized inputs/operation;
repeating it returns the original job, changing inputs returns 409. The dashboard
retains the same key across a failed submission retry within the current page.

Lists accept `limit` (1–50) and `before` (the returned `next_cursor`). Ownership
also applies to pagination cursors. Unknown or other-user IDs return 404. Safe
errors omit submitted values and exception text. Generated request IDs appear in
responses/logs; the originating ID is persisted on jobs and included in worker
completion logs. Logs contain fixed event names, opaque IDs and numeric status,
not headers, tokens, target URLs or model transcripts. Disable ingress access
logging of query strings and redact Authorization/cookies in external tooling.

`GET /health/ready` makes no provider call. Monitor it alongside worker heartbeat
age, queue state counts, interrupted/failed counts and uncertain model reservations.
Metrics are JSON, authenticated and user-scoped; infrastructure operators can query
worker heartbeats directly using a read-only monitoring role. The runtime account
is intentionally not a database maintenance/admin account. Rate buckets and worker
rows currently have no automatic expiry; schedule reviewed retention/archival for
large deployments, preserving accounting needed by active jobs and billing audits.

## SQLite import — offline and opt-in

Stop the local API and back up its entire database directory first. Sign into the
hosted system and create an **empty destination project**. Obtain its ID and your
user ID (`GET /v2/me`). Use a migration-owner connection, not a browser credential.
The importer never infers an owner from legacy unauthenticated records.

```sh
source .venv/bin/activate
python -m pip install -e '.[hosted]'
# Export PATCHPROOF_DATABASE_URL for the destination explicitly; do not print it.
python -m patchproof.hosted.import_sqlite .patchproof/history.sqlite3 \
  --user-id YOUR_HOSTED_USER_ID --project-id YOUR_EMPTY_PROJECT_ID
# Review the validation counts, then explicitly apply to the intended database:
python -m patchproof.hosted.import_sqlite .patchproof/history.sqlite3 \
  --user-id YOUR_HOSTED_USER_ID --project-id YOUR_EMPTY_PROJECT_ID --apply
```

Default is validation-only. Source is opened read-only in a transaction; schema 1,
integrity, foreign keys, IDs, strict report models, CheckSpecs and lineage are
validated. Application is one PostgreSQL transaction; conflicting IDs/targets or
invalid relationships abort it without overwrite. Original scan/job/finding IDs,
reports/specs, timestamps and recheck/retry relationships are preserved. Cursor
sequence numbers are newly allocated in legacy sequence order. Imported unfinished
jobs become interrupted and are never resumed. All imported targets are revoked
and require fresh DNS verification. Imported loopback fixtures remain readable
history but cannot authorize hosted scanning. Historical model usage was not recorded
in SQLite; imported accounting is unknown and is not presented as measured usage.

## Migrations, backup, restore and rollback

Run migrations once with the owner account before starting/upgrading API/workers:

```sh
docker compose --env-file .env.production --profile ops run --rm migrate
```

Startup rejects missing/wrong schema; it does not mutate schema during requests.
The initial revision is `0001_hosted`. Future migrations must be forward-compatible
with the rollout plan. Automatic destructive downgrade is disabled.

Example PostgreSQL backup (keep the dump private and encrypted in backup storage):

```sh
umask 077
docker compose --env-file .env.production exec -T postgres \
  pg_dump -U patchproof_migrator -d patchproof --format=custom > patchproof-backup.dump
```

Use `pg_dump` compatible with the server major version. A dump is not a backup
until a restore is tested. To rehearse restoration, use a **new database**, never
`--clean` against the active production database:

```sh
docker compose --env-file .env.production exec -T postgres \
  createdb -U patchproof_migrator patchproof_restore
docker compose --env-file .env.production exec -T postgres \
  pg_restore -U patchproof_migrator -d patchproof_restore --no-owner --exit-on-error \
  < patchproof-backup.dump
```

Validate counts, exact finding/spec IDs and recheck history in the restored database.
Configure migration/runtime URLs to the restored DB in an isolated environment,
rerun migration grants, and verify with compatible application code. Role credentials
are provisioned separately and are not restored from application reports. For
rollback, stop claims, drain workers, retain the current database, restore the
pre-upgrade backup into a new DB, and switch to the prior reviewed image/config.
Do not edit Alembic version markers or overwrite the original DB to force rollback.

Containers drop capabilities and use non-root application users, read-only roots,
bounded memory/PIDs/CPU and small tmpfs mounts. PostgreSQL stays on an internal
network. There is no Chromium worker in this deployment. Enforce infrastructure
egress rules allowing the DB/identity/provider endpoints and authorized public
HTTP(S) targets while denying other internal/metadata networks; application SSRF
checks remain mandatory even with those rules. Do not allow public database/API
ports, privileged containers, host networking or Docker-socket mounts.

## Verification and remaining deployment gates

See [hosted verification](hosted-verification.md) for exact results and limitations.
Run the controlled hosted suite only against a disposable `patchproof_test*` database;
the fixture intentionally resets its public schema:

```sh
python -m pip install --only-binary=:all: -e '.[dev,api,hosted,browser]'
export PATCHPROOF_TEST_DATABASE_URL='postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:5432/patchproof_test'
python -m pytest -q
cd dashboard
npm ci
npm run typecheck
npm test
node tests/build-secrets.mjs
PATCHPROOF_TEST_STANDALONE=1 node tests/hosted-smoke.mjs
```

The UI harness owns ports 8000, 8776, 3100 and 3101 and uses installed Chrome by
default. Set `PATCHPROOF_BROWSER_CHANNEL=chromium` after installing Node Playwright
Chromium if needed. It uses real JWT verification/JWKS but a test identity gateway
and controlled DNS/target adapters, not a live OIDC authorization-code flow.
A real provider login/logout/refresh/revocation exercise is still required.

Before public deployment: run Docker builds/Compose, test real OIDC and HTTPS,
verify PostgreSQL 17/restore on the target platform, review network/resource rules
and secret provisioning, run the new CI job, and resolve the private security
reporting blocker in SECURITY.md. No release-readiness claim is made here.
