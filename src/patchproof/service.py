import json
from pathlib import Path
from pydantic import ValidationError
from .collector import collect
from .detectors import resolve_rule
from .models import CheckSpec, Finding, Result


class SpecError(ValueError):
    pass


def load_spec(path: str | Path) -> CheckSpec:
    try:
        with Path(path).open('rb') as file:
            data = file.read(65537)
        if len(data) > 65536:
            raise ValueError
        payload = json.loads(data)
        if not isinstance(payload, dict) or set(payload) != set(CheckSpec.model_fields):
            raise ValueError
        spec = CheckSpec.model_validate(payload)
        resolve_rule(spec)
        return spec
    except (OSError, ValueError, ValidationError):
        raise SpecError('Invalid or unsupported CheckSpec; expected schema 1, CSP rule version 1, GET, and the registered condition.') from None


def execute(spec: CheckSpec, *, allow_local=False) -> Result:
    # Revalidate even for Python callers that used model_construct/model_copy.
    spec = CheckSpec.model_validate(spec.model_dump())
    rule = resolve_rule(spec)
    evidence, reason = collect(spec.target_url, allow_local=allow_local)
    run = rule.evaluate(evidence, reason)
    status = 'unverified' if not run.applied else ('resolved' if run.observed_condition else 'still_present')
    return Result(status=status, run=run,
                  finding=Finding(spec=spec, run=run) if status == 'still_present' else None)


def scan(url: str, *, allow_local=False) -> Result:
    return execute(CheckSpec(target_url=url), allow_local=allow_local)


def replay(path: str | Path, *, allow_local=False) -> Result:
    return execute(load_spec(path), allow_local=allow_local)


def export_check(finding: Finding, path: str | Path):
    Path(path).write_text(finding.spec.model_dump_json(indent=2) + '\n', encoding='utf-8')
