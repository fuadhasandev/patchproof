# PatchProof — Phase 3

PatchProof is an open-source website security agent under development. Phase 3 is
an installable, local Python CLI: scan one exact URL, export a portable CheckSpec,
and replay it after a fix. Scan and replay need no API key. Optional investigation
uses OpenRouter only when explicitly requested and configured. Test only websites you own or have
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

## Optional investigation (Phase 3)

First install the project using the macOS setup above. No new dependencies are
required. For an entirely offline demo with a **fake OpenRouter client** and a real
loopback HTTP fixture:

```sh
source .venv/bin/activate
python examples/phase3_demo.py
```

The demo prints the baseline missing-CSP finding, a model-requested evidence read,
a model-requested replay after a simulated fix, and a validated final explanation.
It makes exactly two target GETs and no provider requests. The normal pytest suite
also uses fake providers or mocked provider transports; no API key is needed.

To opt into real OpenRouter calls, configure the environment. `.env.example`
contains blank placeholders; `.env` and `.env.*` (except the example) are ignored
by Git. PatchProof does **not** auto-load dotenv files. Set variables in your shell,
or copy the example to `.env`, edit it locally, and export it:

```sh
cp .env.example .env  # only if .env does not already exist
# Edit .env locally: set your key and a tool-capable OpenRouter model ID.
set -a
source .env
set +a
patchproof investigate https://your-domain.example/ --session-cookie sid --format json
```

Only use an authorized target. With `examples/local_server.py` running in another
terminal, the equivalent loopback command is:

```sh
patchproof investigate http://127.0.0.1:8765 --allow-local --format text
```

With credentials configured this makes **real provider calls**, even though the
target is local. Without both settings it returns the baseline with
`ai_status: not_configured`. Invalid target input exits before OpenRouter is called;
a destination blocked by the baseline address policy returns `target_blocked`.
Unreachable targets remain unverified; they are never inferred to be fixed.

### Scope, budgets, and results

Investigation always runs the deterministic scan first. The model can request only:

- `get_evidence(evidence_id)`: retrieve an allowlisted record from this run.
- `rerun_check(check_id)`: replay a registered check using the operator's original
  URL, cookie configuration, and loopback permission through `service.execute`,
  the same execution path used by file-based replay.

IDs are randomly generated and scoped to the current run. The model cannot supply
URLs, methods, headers, cookie names, or permissions. Python validates the entire
tool-call batch before executing any of it. Unknown names, extra arguments, unknown
IDs, duplicate call IDs, and malformed arguments stop AI processing with
`invalid_tool`; untrusted arguments are never echoed or executed. Every target
attempt still enforces the connection-time address policy, TLS checks, redirect
restrictions, and proxy restrictions.

Limits are **three model requests**, **two follow-up target attempts** in addition
to the baseline, and eight tool calls per model turn. Failed requests count too.
Calls are executed sequentially. Hitting a limit returns `budget_exhausted` and
retains all collected results. Provider requests use a fixed HTTPS endpoint,
20-second HTTPX operation timeouts, no redirects/proxies/retries, a 2,048-token
output cap, and a 256 KiB response cap. These are per-operation timeouts, not a
single end-to-end investigation deadline.

JSON includes `baseline`, `ai_status`, `ai_reason`, `model_turns`,
`followup_requests`, `tool_events`, `followups`, the sanitized `evidence` ID map,
optional `explanation`, and fixed `limitations`. Text includes the same outcomes
and requested tools. Baseline findings remain separate from follow-up results.
AI status is `completed`, `not_configured`, `target_blocked`, `provider_error`,
`invalid_tool`, `invalid_response`, or `budget_exhausted`.

The final model response must be JSON with `claims` and `limitations`. Each claim
has nonempty `evidence_ids`, an `outcome` that must match every referenced record,
and a bounded `explanation`. Unknown references or conflicting outcomes reject the
whole explanation. Limitations are selected from a fixed vocabulary:
`presence_only`, `single_response`, `unverified_checks`,
`no_exploitation_assessment`, and `model_uncertainty`. Free-form model explanations
are advisory, not additional verified findings; references cannot prove that every
sentence is correct. Invalid responses and provider failures fall back to the
retained deterministic report. A disappearing cookie is unverified on replay,
not resolved.

| Investigation exit | Meaning |
| --- | --- |
| 0 | Baseline and any follow-ups have no unverified outcomes; findings may exist |
| 2 | Invalid input, unverified baseline, or any unverified follow-up |

AI availability is best-effort: missing configuration, provider failures, invalid
AI output, and budget exhaustion do not by themselves change the deterministic
exit code. Automation must inspect `ai_status` if it requires AI completion.
Existing scan/replay exit codes and schema 1/2 CheckSpecs are unchanged.

### Exactly what leaves the machine

The target receives the same bounded GET as scan, plus up to two authorized
follow-up GETs; target DNS resolution also occurs. OpenRouter and its selected
model provider receive the static instructions, tool/response schemas, selected
model ID, opaque check/evidence IDs, rule IDs and detector versions, deterministic
statuses/applicability, observed-condition booleans, HTTP status codes, HTTPS/HTML
flags, CSP/HSTS presence flags, and (for a configured-cookie check) counts of issued,
insecure, and unparseable instances. Follow-up turns include only validated tool
calls and the same allowlisted records. Target data is explicitly marked untrusted.

**Target URLs/hosts/paths, cookie names and values, raw headers, bodies, tokens,
CheckSpecs, permissions, and raw exception messages are not sent to the model.**
The API key is sent only as the Authorization header to the fixed OpenRouter API
endpoint; it is never placed in messages or output. Local deterministic reports
retain URLs and configured cookie names as before. Investigation creates no history
files and does not export model prose as regression checks. Normal scan/replay
never read OpenRouter configuration or make model calls.

The adapter follows OpenRouter's official
[Chat Completions tool-calling documentation](https://openrouter.ai/docs/guides/features/tool-calling):
function definitions in `tools`, assistant `tool_calls` with JSON-string arguments,
and matching `role: tool` replies. Tool schemas are sent on every turn. Choose a
model that supports tools; models needing provider-specific reasoning replay or
strict structured-output options may fall back to deterministic results.

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

Each scan or replay sends at most one GET to the supplied target, plus system DNS
resolution for its hostname. These commands have no model calls, telemetry, cookies, credentials,
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

Playwright, FastAPI, dashboard, history, more detectors, and hosted domain
verification are deferred. Website content must remain
untrusted data. A model may request a registered tool; application policy must
authorize each action and enforce scope and budgets before execution. A model or
imported spec cannot grant network access or execute arbitrary commands.

Licensed under Apache-2.0; see `LICENSE`.
