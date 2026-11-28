# PatchProof local dashboard

See the repository [README](../README.md#api-and-dashboard) for installation,
server-only credentials, API startup, fixture configuration, and verification.

- URL: http://localhost:3000
- Backend: http://127.0.0.1:8000 (authenticated, no browser CORS)
- `npm run dev`: Next.js development server bound to localhost
- `npm run typecheck`, `npm test`, `npm run build`: checks
- `npm run test:browser`: isolated HTTPS browser detector scan/export/fix/replay smoke test
- `npm run test:history`: owns temporary servers/database, restarts API, verifies history and rechecks
- `npm run test:e2e`: Chrome smoke test; API/dashboard running and fixture port 8765 free

Never prefix the server credential with `NEXT_PUBLIC_`. OpenRouter configuration
belongs to the backend process only. The local workbench must not be exposed
publicly. Separate deployment requirements are documented in the
[basic-report guide](../docs/basic-reports.md) and
[authenticated hosted runbook](../docs/production.md).

## Frontend design and verification

The checker, report, and Advanced workbenches share emerald theme tokens in
`app/globals.css`, bundled Geist Sans/Mono fonts, Lucide icons, and common site
navigation. The theme follows the system setting until the user chooses a theme;
that preference is stored locally. Motion respects `prefers-reduced-motion`.

Reports distinguish passed, needs-attention, and unverified checks without an
overall security score. Sample data makes no API calls. Rechecks preserve the
original URL and inputs even if the URL field is edited. Technical rule IDs are
inside expandable details. API routes, credentials, and access policies are
unchanged by the design update.

On Vercel (`VERCEL=1`), Advanced shows feature availability and setup links without
mounting either workbench. Other supported environments retain local mode or the
authenticated hosted dashboard according to `PATCHPROOF_MODE`.

- `npm run test:design`: Chrome layout/state checks at 1440, 768, and 390 pixels,
  in both themes; includes Vercel availability and mocked local/hosted workbenches.
  Screenshots are written to ignored `test-results/design/`.
- `npm run test:checker`: real local controlled fixture, sample, comparison, and
  mocked hosted domain-verification flow.
- `node tests/basic-smoke.mjs`: public basic-report integration with a controlled backend.
- `npm run test:history` and `npm run test:browser`: persistence, export, fixes,
  rechecks, and unavailable-target behavior.
- `node tests/build-secrets.mjs`: production build and fake-secret exclusion check.

If IPv4 port 3000 is already in use, set `PATCHPROOF_SMOKE_IPV6=1` for the checker,
history, browser, or existing-server E2E tests. This changes only the test listener
and browser DNS mapping; requests still use `localhost:3000`, and the local access
policy remains unchanged. For the optional browser detector, point
`PATCHPROOF_CHROMIUM_EXECUTABLE` to an installed supported Chrome executable if
Playwright's default Chromium is unavailable. Do not disable isolation or TLS checks.
