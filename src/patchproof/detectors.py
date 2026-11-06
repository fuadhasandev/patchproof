"""Pure typed detectors. No network I/O or imported expressions."""
from .models import CheckSpec, CheckRun, Evidence


class CSPRule:
    rule_id = 'http.csp.present'
    detector_version = '1'
    expected_condition = 'nonempty-content-security-policy'

    def evaluate(self, evidence: Evidence, reason: str | None = None) -> CheckRun:
        if reason is None:
            if evidence.status_code is None:
                reason = 'No response metadata available.'
            elif 300 <= evidence.status_code < 400:
                reason = 'Redirect response; redirects are not followed.'
            elif not 200 <= evidence.status_code < 300:
                reason = 'Unsuccessful response.'
            elif not evidence.is_html:
                reason = 'Response is not HTML.'
        return CheckRun(applied=reason is None,
                        observed_condition=evidence.csp_present if reason is None else None,
                        evidence=evidence, reason=reason)


RULES = {CSPRule.rule_id: CSPRule()}


def resolve_rule(spec: CheckSpec):
    rule = RULES.get(spec.rule_id)
    if (rule is None or spec.schema_version != '1' or spec.method != 'GET'
            or spec.detector_version != rule.detector_version
            or spec.expected_condition != rule.expected_condition):
        raise ValueError('Invalid or unsupported CheckSpec.')
    return rule
