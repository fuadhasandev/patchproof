# PatchProof local dashboard

See the repository [README](../README.md#local-dashboard-phase-4) for installation,
server-only credentials, API startup, fixture configuration, and verification.

- URL: http://localhost:3000
- Backend: http://127.0.0.1:8000 (authenticated, no browser CORS)
- `npm run dev`: Next.js development server bound to localhost
- `npm run typecheck`, `npm test`, `npm run build`: checks
- `npm run test:e2e`: Chrome smoke test; API/dashboard running and fixture port 8765 free

Never prefix the server credential with `NEXT_PUBLIC_`. OpenRouter configuration
belongs to the backend process only. No production/public deployment is supported.
