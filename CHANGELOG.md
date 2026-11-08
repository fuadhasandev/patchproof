# Changelog

## 0.1.0 — first release candidate (unreleased)

- Deterministic CSP/HSTS presence and explicitly named cookie Secure checks.
- Evidence reports, versioned CheckSpec export and replay (schemas 1, 2 and 3).
- Optional bounded OpenRouter investigation with deterministic fallback.
- Optional macOS-isolated Chromium static mixed-content-reference check.
- Authenticated loopback FastAPI API, single-worker queue, SQLite schema 1,
  immutable findings, restart history, interrupted-job recovery and rechecks.
- Local Next.js dashboard with evidence inspection, downloads and scan history.
- Release packaging checks, independent extra installs, CI, contribution/security
  guidance and controlled fixture acceptance workflows.

Limitations: presence-only HTTP checks; no authentication, crawling or exploit
assessment; browser isolation unavailable outside macOS; no hosted/multi-user
operation. Exact runtime compatibility and verification results are recorded in
`docs/releases/verification-0.1.0.md`.

Publication is blocked until a private vulnerability-reporting route is enabled
and verified. CI runner combinations must pass before tagging. Nothing is published
by these preparation changes.
