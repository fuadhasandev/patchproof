# PatchProof — Phase 2

PatchProof is an open-source website security agent under development. Phase 2 is
an installable, local Python CLI: scan one exact URL, export a portable CheckSpec,
and replay it after a fix. No API key is needed. Test only websites you own or have
permission to test.

## macOS setup

Use Python 3.11 or newer. From this workspace:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

## Copy-paste local demo

In terminal 1, from the project directory:

```sh
source .venv/bin/activate
python examples/local_server.py
```

In terminal 2, from the same directory (start without `.demo-csp` present):

```sh
source .venv/bin/activate
patchproof scan http://127.0.0.1:8765 --allow-local --format text
patchproof scan http://127.0.0.1:8765 --allow-local --export-check csp-check.json
patchproof replay csp-check.json --allow-local --format json
echo "Replay exit: $?"  # 1: still present
# Enable CSP on the same URL:
touch .demo-csp
patchproof replay csp-check.json --allow-local --format json
echo "Replay exit: $?"  # 0: resolved
# Imported specs cannot grant loopback access:
patchproof replay csp-check.json --format json
echo "Replay exit: $?"  # 2: unverified, blocked destination
```

Stop the server with Ctrl-C. Delete `.demo-csp` before repeating the missing-header
demo. A public target uses the same commands without `--allow-local`.

## Phase 2 checks and export

| Stable rule ID (detector version 1) | Applicability | What is checked |
| --- | --- | --- |
| `http.csp.present` | Successful HTML response | Nonempty Content-Security-Policy; unchanged Phase 1 behavior |
| `http.hsts.present` | Successful HTTPS response, including non-HTML | Nonempty Strict-Transport-Security |
| `http.session-cookie.secure` | Successful HTTPS response issuing an explicitly configured name | Every observed instance of that name has Secure |

CSP and HSTS check **presence only**, not policy strength. HSTS `max-age=0`
therefore passes this narrow rule. Cookie names are case-sensitive ASCII tokens
(1–256 characters). Repeat `--session-cookie` to configure multiple names; duplicate
names are deduplicated. Separate Set-Cookie fields stay separate, including fields
with a comma in Expires. No cookie values are retained. Any definite instance
without Secure fails the rule. A matching malformed field makes the check
unverified unless another instance already proves the condition fails.

For an HTTPS website you own or have permission to test, replace the target below:

```sh
patchproof scan https://your-domain.example/ --session-cookie sid --session-cookie session --format json
patchproof scan https://your-domain.example/ --session-cookie sid --export-checks checks
patchproof replay checks/001-http.csp.present.json --format json
# Replay every exported finding (each replay makes its own single GET):
for check in checks/*.json; do patchproof replay "$check" --format json; done
```

Export file names are numbered in finding order: CSP, HSTS, then configured cookie
names. Only findings are exported, so inspect the directory before choosing a
single file. Names never become filesystem paths. `--export-check FILE` still
works when there is exactly one finding; with multiple findings it directs you
to `--export-checks DIR`. The directory must be new. Both modes refuse to overwrite
existing destinations. An I/O failure during directory export can leave partial
files; choose a new directory when retrying. The export options are mutually exclusive.

Run the complete HTTPS scenario locally, without DNS or external requests:

```sh
python examples/phase2_demo.py
```

This controlled demo mocks HTTPcore response metadata, runs the actual CLI through
Typer, exports three checks, and demonstrates cookie replay still present → resolved
→ unverified after the cookie disappears. It does not change production TLS or
network policy. The original loopback HTTP demo above exercises real sockets;
HSTS and configured-cookie checks are skipped there because it uses HTTP.

## Results and CI

| Replay exit | Meaning |
| --- | --- |
| 0 | Resolved: the original detector applies and its expected condition is met |
| 1 | Still present: the original detector applies and its expected condition fails |
| 2 | Unverified or invalid input/spec: the original check cannot be evaluated or does not apply |

Scan exits 0 when checks are evaluated or intentionally skipped, whether findings
exist or not, and 2 when any check is unverified or input/export fails. CSP on a
non-HTML response remains unverified, as in Phase 1. HTTP skips HTTPS-only checks;
no configured names or no matching issued cookie skips the cookie check. Skips
carry reasons and are never treated as evidence of a fix. During replay, every
skip becomes **unverified**, including a cookie that is no longer issued.
Timeouts, redirects, unsuccessful responses, blocked destinations, and malformed
matching cookie evidence are also unverified. Redirects are never followed.

Text and JSON expose rule IDs, applicability, sanitized evidence, coverage, and
remediation. JSON scan output contains `checks` and `findings`; the legacy `run`
and `finding` accessors still refer to CSP. The top-level scan status gives priority
to unverified checks, then findings, then resolved. Replay remains a single `run`
and optional `finding`. Runtime errors use an `error` object; CLI syntax errors
use Typer's normal stderr output.

Missing CSP is a **configuration observation**, not proof of exploitation. A
present header passes this rule only; the policy's strength is not assessed.
HTML means a `Content-Type` of `text/html` or `application/xhtml+xml` (parameters
ignored), and success means HTTP 200–299. Whitespace-only CSP is considered absent;
Content-Security-Policy-Report-Only does not satisfy this rule.

## Scope, network policy, and privacy

Each run sends at most one GET to the supplied target, plus system DNS resolution
for its hostname. There are no model calls, telemetry, cookies, credentials,
retries, redirect following, crawling, or environment proxy use. HTTP and HTTPS
only; credentials, query strings, fragments, malformed URLs, and nonpublic IPs
are rejected. `--allow-local` adds only loopback addresses, independently on every
scan/replay. Private LAN, link-local, multicast, and other nonpublic destinations
remain blocked. All DNS answers must pass policy; a mixed public/private answer
is rejected. The connection uses the validated numeric socket address directly,
with the original hostname retained for Host, SNI, and certificate verification.
A fresh policy-enforcing connection pool is created per run.

Requests have a five-second total I/O deadline, including DNS wait, connection,
TLS, and response headers. A timed-out OS DNS lookup may finish in a daemon
thread, but cannot open a target connection or delay CLI exit. HTTP/1.1 header buffering is bounded by HTTPcore/h11.
The response body stream is never consumed. A network read for headers may also
receive some body bytes in the same packet; those bytes are discarded on close.
Redirect locations are neither followed nor retained.

Only allowlisted evidence is retained: status code, HTTPS/HTML classification,
CSP/HSTS presence, configured cookie names, and counts of matching, insecure, and
unparseable cookie fields. Cookie values, raw headers, response bodies, and network exception text
are excluded from reports and logs. HTTPX/HTTPcore diagnostic loggers are disabled
to prevent raw-header logging. This also affects those loggers in an embedding
Python process. CheckSpecs save schema version, rule ID, detector version, exact
normalized target URL, GET method, and the registered expected condition. New HSTS/cookie specs use schema 2 with validated rule parameters;
cookie specs include the exact configured cookie name. CSP continues exporting
the original six-field schema 1, and existing Phase 1 files remain replayable. Specs
save no results or authorization. JSON finding reports include this spec and its
failed CheckRun; resolved/unverified reports contain the CheckRun. Paths in target
URLs are retained, so do not supply URLs with secrets in their paths.

## Python API and architecture

```python
from patchproof import scan, export_checks, replay

result = scan('http://127.0.0.1:8765', allow_local=True, session_cookies=['sid'])
if result.findings:
    export_checks(result.findings, 'new-checks')
result = replay('new-checks/001-http.csp.present.json', allow_local=True)
print(result.status)
```

`policy.py` validates scope and addresses; `collector.py` enforces that policy at
connection time and produces typed evidence; `detectors.py` evaluates that evidence
without I/O through a registry keyed by (rule ID, detector version); `service.py` orchestrates scan/export/replay; `reporting.py` and
`cli.py` present results. Pydantic models reject extra fields and conflicting
versions, methods, rules, and expected conditions. Specs are limited to 64 KiB on
load. Imported expressions, headers, commands, or executable code are never used.
The HTTPcore `SyncStream` adapter is an internal dependency; HTTPcore is constrained
to the 1.0 release line and covered by connection tests.

The offline pytest suite uses controlled loopback fixtures and network mocks,
including a DNS rebinding regression. No public internet is needed for tests.
Dependency installation does need package-index access.

## Later phases and limitations

This phase checks one response, two header-presence conditions, and explicitly
named cookie Secure attributes; it does not inspect body markup,
policy strength, browser behavior, or other vulnerabilities. Failed DNS/address
selection is unverified; no fallback address or retry is attempted. Cookie parsing
is conservative and is not a browser cookie jar. It does not infer session cookie
names, authenticate, assess HttpOnly/SameSite, or evaluate cookie scope and lifetime.

OpenRouter investigation, Playwright, FastAPI, dashboard, history, more detectors,
and hosted domain verification are deferred. Future website content must remain
untrusted data. A model may request a registered tool; application policy must
authorize each action and enforce scope and budgets before execution. A model or
imported spec cannot grant network access or execute arbitrary commands.

Licensed under Apache-2.0; see `LICENSE`.
