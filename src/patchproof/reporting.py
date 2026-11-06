from .models import Result


def render(result: Result, format: str) -> str:
    if format == 'json':
        return result.model_dump_json(indent=2)
    label = {'resolved': 'Resolved: CSP header is nonempty.',
             'still_present': 'Still present: missing CSP header (configuration observation).',
             'unverified': 'Unverified: ' + (result.run.reason or '')}[result.status]
    evidence = result.run.evidence
    lines = [label, f'Status: {evidence.status_code}; HTML: {evidence.is_html}; CSP present: {evidence.csp_present}']
    if result.finding:
        lines.append('Suggested fix: ' + result.finding.suggested_fix)
    lines.append('This rule checks header presence only; it does not assess policy strength.')
    return '\n'.join(lines)
