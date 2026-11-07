import json
from pathlib import Path
from .collector import collect
from .cookies import validate_cookie_name
from .detectors import RULES, resolve_rule
from .models import CheckSpec, ExtendedCheckSpec, BrowserCheckSpec, Spec, Finding, Result, ScanResult


class SpecError(ValueError):
    pass


def validate_spec(payload) -> Spec:
    if not isinstance(payload, dict):
        raise ValueError
    model = {'1': CheckSpec, '2': ExtendedCheckSpec, '3': BrowserCheckSpec}.get(payload.get('schema_version'))
    if model is None or set(payload) != set(model.model_fields):
        raise ValueError
    spec = model.model_validate(payload)
    resolve_rule(spec)
    return spec


def load_spec(path: str | Path) -> Spec:
    try:
        with Path(path).open('rb') as file:
            data = file.read(65537)
        if len(data) > 65536:
            raise ValueError
        return validate_spec(json.loads(data))
    except (OSError, ValueError, TypeError):
        raise SpecError('Invalid or unsupported CheckSpec; use a supported schema, registered rule/version, GET, and valid rule parameters.') from None


def evaluate(spec, evidence, reason, *, replaying=False):
    rule = resolve_rule(spec)
    run = rule.evaluate(evidence, reason, getattr(spec, 'parameters', {}))
    status = ('resolved' if run.observed_condition else 'still_present') if run.applied else (
        'skipped' if run.applicability == 'skipped' and not replaying else 'unverified')
    return Result(status=status, run=run,
                  finding=Finding(spec=spec, run=run, title=rule.title,
                                  suggested_fix=rule.remediation) if status == 'still_present' else None)


def execute(spec: Spec, *, allow_local=False) -> Result:
    spec = validate_spec(spec.model_dump())
    if isinstance(spec, BrowserCheckSpec):
        from .browser import collect_browser
        evidence, reason = collect_browser(spec.target_url, allow_local=allow_local)
        return evaluate(spec, evidence, reason, replaying=True)
    parameters = getattr(spec, 'parameters', {})
    names = (parameters['cookie_name'],) if 'cookie_name' in parameters else ()
    evidence, reason = collect(spec.target_url, allow_local=allow_local, session_cookies=names)
    return evaluate(spec, evidence, reason, replaying=True)


def scan(url: str, *, allow_local=False, session_cookies=(), browser=False) -> ScanResult:
    names = tuple(dict.fromkeys(validate_cookie_name(n) for n in session_cookies))
    csp = CheckSpec(target_url=url)
    specs = [csp, ExtendedCheckSpec(target_url=csp.target_url, rule_id='http.hsts.present',
             expected_condition='nonempty-strict-transport-security', parameters={})]
    specs.extend(ExtendedCheckSpec(target_url=csp.target_url, rule_id='http.session-cookie.secure',
                 expected_condition='all-observed-instances-secure', parameters={'cookie_name': name})
                 for name in names)
    evidence, reason = collect(csp.target_url, allow_local=allow_local, session_cookies=names)
    checks = [evaluate(spec, evidence, reason) for spec in specs]
    if not names:
        rule = RULES[('http.session-cookie.secure', '1')]
        # No configuration is an intentional skip, even if collection failed.
        run = rule.evaluate(evidence, reason)
        checks.append(Result(status='skipped', run=run))
    if browser:
        from .browser import collect_browser
        browser_evidence, browser_reason = collect_browser(csp.target_url, allow_local=allow_local)
        checks.append(evaluate(BrowserCheckSpec(target_url=csp.target_url), browser_evidence, browser_reason))
    findings = tuple(check.finding for check in checks if check.finding is not None)
    status = ('unverified' if any(c.status == 'unverified' for c in checks) else
              'still_present' if findings else 'resolved')
    # Preserve the Phase 1 single-check accessors alongside complete scan results.
    return ScanResult(status=status, run=checks[0].run, finding=checks[0].finding,
                      checks=tuple(checks), findings=findings)


def replay(path: str | Path, *, allow_local=False) -> Result:
    return execute(load_spec(path), allow_local=allow_local)


def export_check(finding: Finding, path: str | Path):
    spec = validate_spec(finding.spec.model_dump())
    with Path(path).open('x', encoding='utf-8') as file:
        file.write(spec.model_dump_json(indent=2) + '\n')


def export_checks(findings, directory: str | Path):
    """Reserve a new directory, so no existing check can be overwritten."""
    directory = Path(directory)
    specs = [validate_spec(f.spec.model_dump()) for f in findings]
    if not specs:
        raise ValueError('No findings to export.')
    directory.mkdir(parents=True, exist_ok=False)
    for index, spec in enumerate(specs, 1):
        # Cookie names never become paths; stable rule IDs and sequence only.
        with (directory / f'{index:03d}-{spec.rule_id}.json').open('x', encoding='utf-8') as file:
            file.write(spec.model_dump_json(indent=2) + '\n')
