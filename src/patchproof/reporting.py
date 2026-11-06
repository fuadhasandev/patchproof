from .models import Result, ScanResult


def render(result: Result, format: str) -> str:
    if format == 'json':
        return result.model_dump_json(indent=2)
    checks = result.checks if isinstance(result, ScanResult) else (result,)
    lines = ['Overall: ' + result.status.replace('_', ' ')]
    for check in checks:
        run = check.run
        lines.append(f'{run.rule_id}@{run.detector_version}: {check.status.replace("_", " ")} '
                     f'(applicability: {run.applicability})')
        if run.cookie_name is not None:
            lines.append('Cookie name: ' + run.cookie_name)
        if check.finding:
            lines.append(check.finding.title + ' (configuration observation)')
        if run.reason:
            lines.append('Reason: ' + run.reason)
        lines.append('Evidence: ' + run.evidence.model_dump_json())
        lines.append('Coverage: ' + run.coverage)
        lines.append('Remediation: ' + run.remediation)
    return '\n'.join(lines)
