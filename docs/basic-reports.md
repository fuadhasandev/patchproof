# Public basic reports: Render + Vercel

The original homepage used `/api/scans` → the loopback-only local FastAPI API,
 or `/api/hosted/*` → authenticated `/v2/*` with DNS ownership verification.
Neither was a dedicated no-login report endpoint.

With `PATCHPROOF_BASIC_BACKEND_URL` configured, the homepage's **Check website**
and **Check again** now use:

`WebsiteChecker.run` → `POST /api/basic-reports` (Next.js server) →
`POST /v1/basic-reports` (`patchproof.basic_api:create_app`) → `service.scan` →
`collector.collect` → `PolicyBackend.connect_tcp`.

Only `{ "target_url": "https://your-public-site.example/" }` is accepted.
The Next.js server adds a shared service credential; the visitor needs no login.
The report is returned synchronously, without a database, worker queue, or saved history.
The existing local Advanced workbench and authenticated hosted Advanced routes remain separate.
Without the basic backend variable, the existing local/hosted homepage behavior remains available.

## Render web service

Use repository root (leave Root Directory blank), Python runtime, one instance:

- Build command: `python -m pip install '.[api]'`
- Start command: `python -m uvicorn patchproof.basic_api:create_app --factory --host 0.0.0.0 --port $PORT --workers 1 --no-access-log`
- Health check path: `/health`
- Required secret: `PATCHPROOF_BASIC_TOKEN`, a random value of at least 32 characters.
  Generate with `python -c 'import secrets; print(secrets.token_hex(32))'` and save the
  same value in Vercel. Do not commit it.
- `PORT` is supplied by Render. Use Python 3.11 or newer.

No `PATCHPROOF_API_TOKEN`, fixture origin, database URL, OIDC, OpenRouter, or browser
settings are required. There is deliberately no production fixture/address-policy bypass.

## Vercel

Root Directory: `dashboard`; framework preset: Next.js; install: `npm ci`;
build: `npm run build`. Vercel manages the server start command.

Set these **server-only** variables for the deployment environment:

| Variable | Value |
| --- | --- |
| `PATCHPROOF_BASIC_BACKEND_URL` | `https://YOUR-SERVICE.onrender.com` (origin only) |
| `PATCHPROOF_BASIC_TOKEN` | Same random secret as Render |
| `PATCHPROOF_PUBLIC_ORIGIN` | Exact dashboard origin, e.g. `https://patchproof.example`, without trailing slash |

Leave `PATCHPROOF_MODE` unset for the local Advanced workbench; do not route that
workbench to the public basic service. The homepage selects basic reports from
`PATCHPROOF_BASIC_BACKEND_URL`, independently of Advanced mode.
Never add a `NEXT_PUBLIC_` prefix. Redeploy after setting/changing variables.
Use the exact preview origin if enabling previews; a mismatched origin is rejected.
No CORS configuration is needed because browsers only call their same-origin Next.js route.

## Bounds and semantics

- One normal metadata-only GET; no body analysis, redirects, retries, cookies, AI,
  crawling, or browser execution. CSP and HSTS use the existing presence rules.
  The unconfigured cookie check is explicitly skipped.
- Public HTTP(S) destinations only. Existing URL validation also rejects credentials,
  query strings, and fragments. DNS resolves at connection time, rejects mixed
  public/private answers, and connects to the validated numeric address while keeping
  the hostname for TLS verification. Private, loopback, link-local and reserved IPs
  remain blocked. Proxy environment variables are ignored.
- Five-second total target deadline covers DNS, connect, TLS and response headers.
  Next.js allows 12 seconds for its backend call (20-second function limit).
- 4 KiB incoming JSON maximum; 2,048-character URL maximum; extra fields rejected.
- Global rolling quota: 30 authenticated submissions/minute, including invalid bodies;
  maximum four concurrent target checks. Excess returns 429 with `Retry-After`.
  The quota does not trust caller-supplied IP headers. Direct API access requires the
  service secret. Limits are in memory and reset on restart; **keep one worker and
  one instance**. A shared limiter is required before scaling horizontally.
- Unreachable, blocked, redirected and timed-out targets produce unverified evidence,
  never a passing result. Raw response headers, cookies and body are not returned.
  Reports are marked `Cache-Control: no-store`.

## Verification

From repository root:

```sh
.venv/bin/python -m pytest tests/test_basic_api.py tests/test_network.py -q
cd dashboard
npm test
npm run build
node tests/basic-smoke.mjs
```

The browser test starts the production Next.js build and real FastAPI on ports
3017 and 8017 and clicks the homepage without a session. The test-only entrypoint
`tests/basic_e2e_fixture.py` maps `fixture.example` to a controlled ephemeral local
HTTP server at the collector resolver boundary. Never deploy that entrypoint.
Production has no loopback exception. Unit tests separately exercise the real
address policy (including rebinding/mixed-answer protection), deadlines, exact
request counts, redirect handling, credential checks, body limits and rate limits.

Platform references: [Render FastAPI deployment](https://render.com/docs/deploy-fastapi)
and [Vercel environment variables](https://vercel.com/docs/environment-variables).
