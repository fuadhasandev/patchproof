# v0.1.0 acceptance record

Prepared 2026-11-08 (Asia/Dhaka). **Publication blocked**, not marked release-ready.
No commits, pushes, tags, releases or package uploads were made.

## Environment and evidence

- macOS 13.7.7, Intel; CPython 3.13.7 and temporary CPython 3.11.18.
- Node 20.19.4, npm 10.8.2, Next.js 16.4.5 from the existing package lock.
- Google Chrome 156.0.8078.80 via `PATCHPROOF_CHROMIUM_EXECUTABLE`.
- Python 3.13 integration environment: Playwright 1.64.1, FastAPI 0.162.0,
  HTTPX 0.28.1, Pydantic 2.14.3. Fresh Python 3.11 installed FastAPI 0.162.2.
- Only controlled loopback HTTP/HTTPS fixtures and mocked AI providers were used
  for acceptance. Package installation and repository/license checks used network.

## Passed

- Python 3.13 full suite with `PATCHPROOF_TEST_BROWSER=1`: **191 passed, no skips**.
- Python 3.11 baseline suite: **186 passed, 5 browser tests intentionally skipped**.
- Standalone macOS browser suite: **32 passed on Python 3.13**, and **32 passed
  on the installed Python 3.11 wheel** (Playwright 1.64.1). Covers schema-3
  export/fix/replay, forbidden origins, redirects, incomplete coverage, unavailable
  isolation, process cleanup, API persistence and redaction.
- `npm ci`, `npm run typecheck`, `npm test` (**3 passed**) and production build.
- `node tests/build-secrets.mjs`: **98 frontend assets** (client assets and generated
  app HTML/routes) exclude fake API/OpenRouter credentials and sensitive fixture data.
- Documented `npm start`: production dashboard returns HTTP 200 with PatchProof
  markup at `http://localhost:3000`; no credential appears in returned HTML.
- `npm run test:history`: scan, inspect, schema-1 download, abrupt API restart,
  reopen saved report, fix, resolved recheck, stopped fixture, unverified recheck.
- `npm run test:browser`: controlled HTTPS, isolated browser finding, schema-3
  download, API restart/history, fix/resolved, stopped target/unverified.
- Both UI acceptance tests inspect their retained SQLite files/sidecars and server
  logs after shutdown: no test credential or sensitive fixture evidence. Original
  findings and recheck timelines survive restart unchanged.
- Fixture CLI scan/evidence/export/replay; exits 1 while present, 0 after fix,
  2 when blocked/unavailable. Missing AI configuration and mocked provider failures
  preserve baseline findings. Schema-1/2 compatibility, SQLite schema 0→1,
  unsupported-schema rejection, restart interruptions and immutable originals.
- Wheel and sdist built in isolated build environments; wheel is built from the
  sdist. `twine check` passes. All Python runtime modules, the browser worker,
  inline SQLite migration and exact Apache license are included. The sdist also
  includes examples, tests, contributor scripts and locked dashboard sources.
- Independent fresh wheel installs outside the checkout: **core, api, browser,
  dev**. CLI help/scan/investigate/replay and `pip check` pass in each. Core has
  neither FastAPI nor Playwright. AI has no optional dependency to install.
  API installation also exercises SQLite initialization, authenticated capabilities,
  application version and Uvicorn's entry point.
- Archive inventory excludes environments, secrets, databases, certificates,
  logs, reports, caches, node_modules, built dashboard and test artifacts.
- LICENSE is byte-identical to the [official Apache-2.0 text](https://www.apache.org/licenses/LICENSE-2.0.txt).
- Public repository remote verified as `https://github.com/fuadhasandev/patchproof`
  with default branch `main`. Local documentation targets/anchors and CI YAML
  syntax/minimal permissions checked. `git diff --check` passes.

## Failed or blocked checks

- Private vulnerability reporting: GitHub API returned **enabled=false**. No
  existing alternative private route is configured. See SECURITY.md.
- Initial sandboxed pytest run could not bind loopback sockets, and sandboxed pip
  could not resolve the package index. Rerunning with the needed local-network and
  installation access passed; these are environment restrictions, not remaining
  product failures. No sandbox control in the product was weakened.

## Unrun / not claimed

- GitHub-hosted workflow execution: requires the maintainer to commit/push first.
  CI defines Python 3.11/3.13 on Ubuntu/macOS, Linux dashboard history tests and a
  separate macOS browser job. Its explicit browser opt-in fails on missing
  dependencies/platform instead of silently skipping. No job has secret access
  configured, checkout credentials are not persisted, and permissions are read-only.
- Linux runtime acceptance locally, native Windows, Python 3.12/3.14+, and other
  Node versions. Metadata's Python >=3.11 and Next's Node >=20.9 minimum do not
  mean every combination has been verified. Native Windows API is unsupported
  (`fcntl`); browser scanning is unavailable on Linux/Windows by design.
- Live OpenRouter requests (intentionally omitted; all AI acceptance uses fakes).
- Playwright's bundled Chromium on this macOS 13 machine. Local browser acceptance
  used installed Chrome; CI installs matching Chromium on macOS 14.
- Public publishing, PyPI installation, tags, commits and pushes (left to maintainer).

## Fixes made during release preparation

- Corrected the build backend floor to setuptools >=77 for the existing SPDX
  license field, consistent with its [official documentation](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).
- Made Python package/API version authoritative in `_version.py`; enforced dashboard
  and lockfile alignment, added explicit sdist contents and archive checks.
- Restored one whitespace difference in the standard license.
- Made explicitly requested browser integration fail on unsupported platforms or
  absent Playwright; added persistent-file and production-asset secret assertions.
- Replaced phase-oriented onboarding with release setup and preserved the detailed
  implementation reference. Added CI, security/contribution guidance and templates.

## Release gate

Enable and verify a private reporting route, update SECURITY.md/release notes,
and obtain green results from every GitHub CI job. Rerun affected checks and
rebuild artifacts after any changes. Until then, keep 0.1.0 unpublished.

Artifacts are prepared locally in `dist/`; `SHA256SUMS` covers the wheel and sdist.
The directory is ignored by Git. Screenshots generated by acceptance tests remain
ignored test artifacts; no illustrative or fabricated screenshots are in the docs.
