# Contributing

Start with [README.md](README.md) for the verified environment, setup, local demo,
and network boundaries. Use controlled fixtures, never public scan targets or
live OpenRouter keys in tests. Read applicable AGENTS.md files before editing.

```sh
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,api]'
python -m pytest -q
cd dashboard
npm ci
npm run typecheck
npm test
node tests/build-secrets.mjs
npm run test:history
```

The history smoke test starts its own API, dashboard and fixture; ports 8000,
3000 and 8765 must be free. It uses installed Chrome by default. To use Playwright
Chromium, run `npx playwright install chromium` and set
`PATCHPROOF_BROWSER_CHANNEL=chromium`. Scanner browser tests additionally require
macOS, the Python browser extra and its Chromium installation; see README.md.
They run in a separate CI job and must not silently skip on missing prerequisites.

## Add a deterministic detector

1. Define the smallest typed, sanitized evidence in `models.py`. Collect it via
   the bounded policy-enforcing collector; do not add network I/O to a detector.
2. Implement a pure rule in `detectors.py` and register its stable `(rule_id,
   detector_version)`. State applicability, expected condition, coverage and
   remediation. Missing evidence must not imply resolution.
3. Add a strict versioned CheckSpec model and validation in `models.py` and
   `service.py`. Permit only registered parameters, GET and the fixed expected
   condition. Reject unknown fields. Never accept permissions or executable code.
4. Keep old schema/version semantics replayable. CSP exports schema 1;
   HSTS/cookie checks use schema 2; the static Chromium rule uses schema 3.
   A changed interpretation needs a new detector version, not a silent rewrite.
5. Add controlled fixture coverage for scan → evidence → export → still present
   → fix → resolved, plus unavailable/inapplicable → unverified, malformed specs,
   prior-version replay, scope enforcement and redaction. AI tests use fakes.
6. Update exact limitations, release notes and dashboard types as needed. Confirm
   immutable originals and SQLite rechecks still work after an API restart.

## Prepare artifacts

The authoritative application version is `src/patchproof/_version.py`.
Setuptools and FastAPI read it. Keep the private dashboard package and lockfile
version aligned; `scripts/check_release.py` enforces this.

```sh
python -m pip install build twine
python -m build
python -m twine check dist/*.whl dist/*.tar.gz
python scripts/check_release.py
```

The checker installs the wheel in five fresh temporary virtual environments
(core, api, browser, dev, hosted) and invokes the real CLI outside the checkout. AI needs
no extra dependency. The sdist contains contributor sources and the dashboard;
the wheel contains the Python application, including inline SQLite migrations
and the isolated browser worker. Dashboard assets are built separately with npm.
`dist/SHA256SUMS` records the locally checked wheel and sdist.

CI has read-only repository permissions, does not persist checkout credentials,
and does not reference secrets or use `pull_request_target`. Keep it that way.
Do not upload fixture databases, raw logs or screenshots as release artifacts.
Run the checks before proposing a change. Tagging, publishing and package uploads
are maintainer actions; the release-preparation workflow does none of them.

The build backend requires setuptools >=77 because SPDX license expressions were
introduced there; see the [official packaging guide](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).

## Hosted backend tests

Install `.[dev,hosted]` and read [the production runbook](docs/production.md).
Set `PATCHPROOF_TEST_DATABASE_URL` to a disposable PostgreSQL database whose name
starts with `patchproof_test`; tests reset its public schema. Never use a real
database. Run `python -m pytest -q tests/hosted`, then build the dashboard and run
`node tests/hosted-smoke.mjs` from its directory. The latter uses controlled identity,
DNS and target fixtures through normal dashboard entry points. No live provider
keys or public scan targets belong in these tests. Alembic's initial schema snapshot
is frozen; add a new revision for subsequent schema changes.
