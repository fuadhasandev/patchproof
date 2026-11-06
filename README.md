# PatchProof — Phase 1

PatchProof is an open-source website security agent under development. Phase 1 is
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

## Results and CI

| Replay exit | Meaning |
| --- | --- |
| 0 | Resolved: successful HTML response has a nonempty CSP header |
| 1 | Still present: successful HTML response lacks a nonempty CSP header |
| 2 | Unverified or invalid input/spec: blocked, timeout, network failure, redirect, unsuccessful response, non-HTML, or unsupported spec |

Scan exits 0 for an evaluated rule (with or without a finding), and 2 for
unverified/invalid input or export failure. `--export-check` writes only when a
finding exists; otherwise it errors and leaves the destination unchanged. Exports
replace the specified file. JSON output is available with `--format json`; runtime
errors use an `error` object. CLI syntax errors use Typer's normal stderr output.

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

Only allowlisted evidence is retained: status code, HTML classification, and CSP
presence. Cookie values, raw headers, response bodies, and network exception text
are excluded from reports and logs. HTTPX/HTTPcore diagnostic loggers are disabled
to prevent raw-header logging. This also affects those loggers in an embedding
Python process. CheckSpecs save schema version, rule ID, detector version, exact
normalized target URL, GET method, and the registered expected condition. They
save no results or authorization. JSON finding reports include this spec and its
failed CheckRun; resolved/unverified reports contain the CheckRun. Paths in target
URLs are retained, so do not supply URLs with secrets in their paths.

## Python API and architecture

```python
from patchproof import scan, export_check, replay

result = scan('http://127.0.0.1:8765', allow_local=True)
if result.finding:
    export_check(result.finding, 'csp-check.json')
result = replay('csp-check.json', allow_local=True)
print(result.status)
```

`policy.py` validates scope and addresses; `collector.py` enforces that policy at
connection time and produces typed evidence; `detectors.py` evaluates that evidence
without I/O; `service.py` orchestrates scan/export/replay; `reporting.py` and
`cli.py` present results. Pydantic models reject extra fields and conflicting
versions, methods, rules, and expected conditions. Specs are limited to 64 KiB on
load. Imported expressions, headers, commands, or executable code are never used.
The HTTPcore `SyncStream` adapter is an internal dependency; HTTPcore is constrained
to the 1.0 release line and covered by connection tests.

The offline pytest suite uses controlled loopback fixtures and network mocks,
including a DNS rebinding regression. No public internet is needed for tests.
Dependency installation does need package-index access.

## Later phases and limitations

This phase checks one response and one header; it does not inspect body markup,
policy strength, browser behavior, or other vulnerabilities. Failed DNS/address
selection is unverified; no fallback address or retry is attempted.

OpenRouter investigation, Playwright, FastAPI, dashboard, history, more detectors,
and hosted domain verification are deferred. Future website content must remain
untrusted data. A model may request a registered tool; application policy must
authorize each action and enforce scope and budgets before execution. A model or
imported spec cannot grant network access or execute arbitrary commands.

Licensed under Apache-2.0; see `LICENSE`.
