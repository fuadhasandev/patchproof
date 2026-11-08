# PatchProof 0.1.0

PatchProof checks website configuration, saves bounded evidence, and exports a
versioned CheckSpec you can replay after a fix. It includes a Python CLI, an
optional local FastAPI server with SQLite history, and a Next.js dashboard.
Deterministic checks work without AI. Optional OpenRouter investigation explains
allowlisted evidence; an optional isolated Chromium visit checks static HTTP
resource references on HTTPS pages. Scan only websites you own or may test.

**Release candidate: not ready to publish until the private reporting route in
[SECURITY.md](SECURITY.md) is configured and verified.** See
[release verification](docs/releases/verification-0.1.0.md) for passed and unrun
checks. No tag, package upload or release has been published by this preparation.

## Verified environment

Local acceptance uses **macOS 13.7.7, CPython 3.11.18 and 3.13.7, Node.js
20.19.4 and npm 10.8.2**. These are the exact verified versions, not a claim about every later
version. Package metadata permits Python >=3.11; CI targets Python 3.11 and 3.13
on macOS/Linux, but those additional runner combinations require a green CI run.
The API's `fcntl` database lock requires macOS/Linux; native Windows is not
supported for the API. Windows CLI compatibility has not been verified.

Next.js 16.4.5's [official installation guide](https://nextjs.org/docs/app/getting-started/installation)
and bundled documentation specify Node >=20.9; that upstream minimum is not our
compatibility test result. Use the existing npm lockfile (`npm ci`). Scanner
browser isolation supports **macOS only**; Linux/Windows return unavailable, not
an unsafe fallback. Installed Google Chrome was used for local browser acceptance.

## macOS setup

Install Python 3.13, Node and Git first. From a new terminal:

```sh
git clone https://github.com/fuadhasandev/patchproof.git
cd patchproof
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,api]'
patchproof --help
python scripts/configure_local.py
cd dashboard
npm ci
npm run typecheck
npm test
npm run build
cd ..
```

For CLI-only use, `python -m pip install .` installs no FastAPI or Playwright.
OpenRouter needs no extra package. The `api`, `browser` and `dev` extras are
independent. The release wheel can also be installed from a local build:

```sh
python -m pip install build
python -m build
python3.13 -m venv /tmp/patchproof-cli
/tmp/patchproof-cli/bin/python -m pip install "$PWD/dist/patchproof-0.1.0-py3-none-any.whl"
cd /tmp
/tmp/patchproof-cli/bin/patchproof --help
```

The wheel is the Python product. Use the repository or source distribution for
the dashboard, examples and contributor tools; no prebuilt dashboard is in the wheel.

### API and dashboard

Run these in separate terminals, each starting from the repository root.
The credential generator writes `.env.api` with mode 0600, does not print its
value, and leaves an existing file unchanged. PatchProof does not auto-load dotenv.

**API:**

```sh
source .venv/bin/activate
set -a
source .env.api
set +a
export PATCHPROOF_DB_PATH="$PWD/.patchproof/history.sqlite3"
# Enable only for the controlled demo below:
export PATCHPROOF_FIXTURE_ORIGIN=http://127.0.0.1:8765
python -m uvicorn patchproof.api:create_app --factory \
  --host 127.0.0.1 --port 8000 --no-access-log
```

**Dashboard:**

```sh
set -a
source .env.api
set +a
export NEXT_TELEMETRY_DISABLED=1
cd dashboard
npm start
```

Open **http://localhost:3000**. `npm run dev` is the development alternative.
Both servers need the same server-only `PATCHPROOF_API_TOKEN` (at least 32
characters). Never use a `NEXT_PUBLIC_` prefix. The dashboard server talks only
to `http://127.0.0.1:8000`; browser requests must use `localhost:3000` and matching
Origin. The API is authenticated, not a browser login page. Use one API process,
without reload or multiple workers. Do not expose or tunnel either server publicly.
Unset `PATCHPROOF_FIXTURE_ORIGIN` and restart the API after the demo.

## Local demo: scan → evidence → export → fix → replay

In terminal 1, from the repository root, ensure `.demo-csp` is absent, then run:

```sh
source .venv/bin/activate
python examples/local_server.py
```

In terminal 2, from the same directory:

```sh
source .venv/bin/activate
mkdir -p .patchproof
patchproof scan http://127.0.0.1:8765 --allow-local --format json
patchproof scan http://127.0.0.1:8765 --allow-local --export-check .patchproof/csp-check.json
patchproof replay .patchproof/csp-check.json --allow-local --format json
echo "$?"  # 1: still present
# The fixture detects this file and starts sending CSP:
touch .demo-csp
patchproof replay .patchproof/csp-check.json --allow-local --format json
echo "$?"  # 0: resolved
```

JSON shows sanitized response status, HTML classification, CSP presence and the
failed rule; the export contains its replay recipe, not the observed evidence.
Stop the fixture with Ctrl-C, then repeat replay: exit 2, `unverified`. An
unavailable target never proves a fix. Without `--allow-local`, even the saved
loopback spec is unverified. Before repeating the demo remove only its generated
`.demo-csp` and `.patchproof/csp-check.json`; exports refuse to overwrite files.

In the dashboard, scan the same URL while the fixture is unfixed, inspect the
finding and download its CheckSpec. Restart the API with the same database and
credential, open **Scan History → Open report**, apply `touch .demo-csp`, and
click **Recheck**. The original remains still present while the new recheck is
resolved. Stop the fixture and recheck again to see unverified. History is not
replaced by the latest outcome. `npm run test:history` automates this sequence
using its own fixture and temporary database (ports 8765, 8000 and 3000 must be free).

## Checks and results

All detectors are version 1. Only failed findings are exported.

| Rule | Spec schema | Exact scope and limitation |
| --- | --- | --- |
| `http.csp.present` | 1 | Nonempty enforcing CSP on a 2xx HTML/XHTML response. No policy-strength assessment; report-only does not count. Non-HTML is unverified. |
| `http.hsts.present` | 2 | Nonempty HSTS on a 2xx HTTPS response. Presence only: even `max-age=0` passes. HTTP is skipped. |
| `http.session-cookie.secure` | 2 | Every observed instance of an explicitly named cookie has Secure on a 2xx HTTPS response. No authentication, inferred session names, HttpOnly/SameSite or lifetime analysis. Absent names/HTTP are skipped; malformed matching fields may be unverified. |
| `browser.mixed-content.references` | 3 | Static HTTP resource references in document attributes/srcset and inline CSS, using `chromium-static-v1`. No JavaScript, crawling or interactions; no claim about arbitrary external CSS or dynamic content. |

Use repeated `--session-cookie sid` options to select case-sensitive cookie names.
`--export-check FILE` requires exactly one finding; `--export-checks NEW_DIR`
exports all findings to numbered files. Both refuse overwrite and are mutually
exclusive. An export I/O failure can leave partial files; retry in a new directory.
Older schema-1/2 specs remain replayable; unknown schemas/rules/versions and extra
fields are rejected. Specs contain no access permission or executable expressions.

| Outcome | Meaning | Replay exit |
| --- | --- | --- |
| `resolved` | The same detector applies and its expected condition is met | 0 |
| `still_present` | The same detector applies and its expected condition fails | 1 |
| `unverified` | Evidence unavailable, incomplete, inapplicable or invalid spec/input | 2 |
| `skipped` | A scan check intentionally does not apply; never proof of a fix | Converted to unverified on replay |
| `interrupted` | API job was queued/running during restart; saved baseline survives, no request resumes | Job state, not a replay exit code |

Scan exits 0 for evaluated/skipped checks, even with findings; 2 for unverified or
invalid input/export. Investigation uses 0/2 for deterministic outcomes; AI failure
alone does not change the exit. Redirects, failed responses, timeouts, a disappeared
cookie, and incomplete browser coverage cannot resolve a finding. Retry an
interrupted job explicitly; retries/rechecks create new immutable history entries.

## Network and evidence boundaries

Baseline scan/replay makes one bounded metadata GET, plus DNS resolution. No
response body is consumed, redirects followed, cookies sent, authentication,
crawling, environment proxies or retries. HTTP/HTTPS only: credentials, queries,
fragments and nonpublic destinations are rejected. All DNS answers must pass
policy; connection uses a validated numeric address with original TLS SNI/Host.
TLS verification stays enabled. The I/O deadline is five seconds.

`--allow-local` permits only loopback, not private LAN addresses. The API's
server-only fixture setting permits one exact literal loopback origin. Requests
and imported specs cannot enable it. Reports/specs retain target URLs (including
paths) and configured cookie names: **never put secrets in target paths**. Raw
headers/bodies, cookie values, credentials and raw network exceptions are excluded.

## Optional OpenRouter

No AI dependency extra is needed. Export these only in the CLI/API terminal:

```sh
export OPENROUTER_API_KEY='your-key'
export OPENROUTER_MODEL='your-tool-capable-model-id'
patchproof investigate http://127.0.0.1:8765 --allow-local --format json
```

The dashboard's AI option uses the backend environment. With either setting
missing, `ai_status` is `not_configured` and baseline findings remain. Provider
failure, invalid tool calls, invalid explanations and exhausted budgets also retain
baseline results. Tests use mocked providers; no live provider is required.

OpenRouter and the selected model provider receive static instructions and schemas,
model ID, opaque per-run IDs, rule/detector IDs, statuses/applicability, boolean
observations, HTTP status, HTTPS/HTML and CSP/HSTS presence flags, and cookie-instance
counts. Follow-ups include validated tool calls and the same allowlisted evidence.
They receive **no target URL/host/path, cookie name/value, raw header/body, CheckSpec,
permission, exception text or browser evidence**. The key is sent only in the
Authorization header to the fixed OpenRouter endpoint. Normal scan/replay make
no model calls. Target DNS and GET traffic still leave the machine as described above.

The model can read current evidence or rerun a registered check; it cannot supply
URLs, headers, methods or permissions. Limits: three model turns, two follow-up
target attempts, eight tools per turn, sequential execution, 20-second provider
operation timeouts and 256 KiB responses. Explanations are advisory; no model prose
becomes an executable check. See [the detailed protocol](docs/reference.md#optional-investigation-phase-3).

## Optional browser scanning

On macOS:

```sh
source .venv/bin/activate
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

Playwright's bundled browser may reject older macOS, including this machine's
macOS 13. The verified alternative is an installed Chrome executable, configured
in the CLI/API terminal:

```sh
export PATCHPROOF_CHROMIUM_EXECUTABLE="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

Add `--browser` to scan/investigate, or enable **Browser check** in the dashboard.
Replay of a schema-3 spec automatically uses the same profile. Chromium runs under
`/usr/bin/sandbox-exec` with direct Internet and outbound Unix-socket access denied;
a denial self-test must pass. Missing dependencies, unsupported OS, failed isolation
or failed launch return unavailable/unverified while preserving baseline HTTP results.

The broker fetches only GETs to the initial exact HTTPS origin. It blocks third
parties, HTTP, query-bearing URLs, redirects, nonpublic addresses and subframe
navigation. No request cookies, authorization or arbitrary page headers are forwarded.
JavaScript/service workers, downloads, popups and WebSockets are disabled. Limits:
one visit per process, 20 seconds, 32 broker requests, 2 MiB per response, 8 MiB
bodies total, 512 reference observations, and a one-second observation window.

An HTTP reference fails even if Chromium upgrades it or policy blocks it. Absence
resolves only after successful navigation and complete supported-profile coverage;
failed/blocked dependencies, frames or exhausted limits make absence unverified.
Only bounded counts, availability/coverage flags, profile and status are retained;
no resource URLs, HTML/CSS, screenshots or raw browser logs enter reports or SQLite.

For the complete controlled certificate setup and scan/export/fix/replay commands,
use the [local HTTPS demo](docs/reference.md#trusted-local-https-demo). It uses
`examples/https_server.py`, `SSL_CERT_FILE` and `PATCHPROOF_BROWSER_CA_FILE` without
altering system trust. Browser tests create their own certificates:

```sh
PATCHPROOF_TEST_BROWSER=1 python -m pytest -q tests/test_browser.py
cd dashboard
npm run test:browser
```

The Node test uses installed Chrome by default; `npx playwright install chromium`
plus `PATCHPROOF_BROWSER_CHANNEL=chromium` selects its separate Playwright browser.
Explicit Python browser opt-in fails if required dependencies/platform are missing.

## SQLite migrations and backups

Default: `.patchproof/history.sqlite3` relative to API working directory. Prefer
an absolute `PATCHPROOF_DB_PATH`. The wheel includes migrations inline in
`patchproof/storage.py`; there is no separate migration-file directory.

```sh
# Stop the API before manual initialization/migration or backup.
python -m patchproof.storage init --database "$PWD/.patchproof/history.sqlite3"
```

Startup runs the same idempotent migration: new/empty schema 0 → schema 1 in a
transaction. Other schema versions fail closed; do not edit `PRAGMA user_version`
to force acceptance. Back up before upgrading. With the API stopped, copy the
whole `.patchproof` directory to a private backup location, preserving SQLite
WAL/SHM files after an abrupt stop. Restore the whole backup while stopped.
The lock file can remain; OS locks are released when a process exits.

History retains original URLs, configured cookie names, sanitized reports/specs,
AI explanations/status, jobs and recheck/retry links. New DB files are mode 0600,
new directories 0700. Storage is not encrypted and has no automatic expiry.
There is one worker and at most eight queued/running jobs; the database lease
rejects another API process. No requests are resumed on restart.

## Tests, contribution and troubleshooting

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md),
[SECURITY.md](SECURITY.md) and [release notes](docs/releases/v0.1.0.md).
The [detailed reference](docs/reference.md) preserves protocol/API and evidence details.

```sh
python -m pytest -q
cd dashboard
npm run typecheck
npm test
npm run build
```

- `Operation not permitted` binding fixture sockets: the execution sandbox must
  allow loopback listeners; do not weaken target policy to work around it.
- Dependency download/DNS errors: installation needs package-index access. Runtime
  fixture tests do not need public scan targets or OpenRouter credentials.
- API unavailable/503: export the same `.env.api` in both server terminals; use
  exactly `localhost:3000` and start the API on `127.0.0.1:8000`.
- Database already in use: stop the other API process; do not delete a live lock
  or start multiple workers. Keep a stable absolute database path across restarts.
- Browser unavailable on older macOS: use the executable override above or a
  supported macOS/Chromium installation. Never disable the isolation requirement.
- HTTPS fixture unverified: regenerate expired certificates and export both trust
  variables in the API/CLI terminal. Do not disable certificate verification.
- Export already exists: choose a new destination. A resolved scan has no finding
  to export. Remove the demo marker to reproduce missing CSP.
- FastAPI tests may emit a Starlette HTTPX deprecation warning; current tests pass.
  This is not an instruction to add another HTTP client to the runtime.

Licensed under the standard [Apache-2.0 license](LICENSE).
